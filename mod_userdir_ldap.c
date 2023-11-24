/*
 * mod_userdir_ldap
 *
 * Copyright (C) 2006,2007 DesigNET, INC.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "util_ldap.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#define USERDIR_LDAP_DEF_FILTER	"objectClass=*"
#define USERDIR_LDAP_DEF_ATTR	"uid"
#define USERDIR_LDAP_DEF_HOME	"homeDirectory"

static APR_OPTIONAL_FN_TYPE(uldap_connection_find) *util_ldap_connection_find;
static APR_OPTIONAL_FN_TYPE(uldap_cache_getuserdn) *util_ldap_cache_getuserdn;
static APR_OPTIONAL_FN_TYPE(uldap_connection_close) *util_ldap_connection_close;

module AP_MODULE_DECLARE_DATA userdir_ldap_module;

typedef struct {
    int		globally_disabled;
    apr_table_t	*enabled_users;
    apr_table_t	*disabled_users;
    char	*userdir;

    int		have_ldap_url;
    char	*url;
    char	*host;
    int		port;
    char	*binddn;
    char	*bindpw;
    char	*basedn;
    char	*filter;
    char	*attribute;
    char        *homeattr;
    int		scope;
    int		secure;
    deref_options deref;
} userdir_ldap_config_t;

static void *
create_userdir_ldap_config(apr_pool_t *p, server_rec *s)
{
    userdir_ldap_config_t *sec =
	(userdir_ldap_config_t *)apr_pcalloc(p, sizeof(userdir_ldap_config_t));

    sec->globally_disabled = 0;
    sec->enabled_users     = apr_table_make(p, 4);
    sec->disabled_users    = apr_table_make(p, 4);
    sec->userdir           = NULL;

    sec->have_ldap_url = 0;
    sec->url           = "";
    sec->host          = NULL;
    sec->binddn        = NULL;
    sec->bindpw        = NULL;
    sec->basedn        = NULL;
    sec->filter        = USERDIR_LDAP_DEF_FILTER;
    sec->attribute     = USERDIR_LDAP_DEF_ATTR;
    sec->homeattr      = USERDIR_LDAP_DEF_HOME;
    sec->secure        = -1;
    sec->deref         = always;

    return sec;
}

#define FILTER_LENGTH MAX_STRING_LEN
static void
userdir_ldap_build_filter(char *filtbuf,
			request_rec *r,
			const char *sent_user,
			const userdir_ldap_config_t *sec)
{
    char *p, *q, *filtbuf_end;
    char *user;

    if (sent_user != NULL) {
	user = apr_pstrdup(r->pool, sent_user);
    }
    else {
	return;
    }

    apr_snprintf(filtbuf, FILTER_LENGTH, "(&(%s)(%s=", sec->filter, sec->attribute);

    filtbuf_end = filtbuf + FILTER_LENGTH - 1;
#if APR_HAS_MICROSOFT_LDAPSDK
    for (p = user, q=filtbuf + strlen(filtbuf);
	 *p && q < filtbuf_end; ) {
	if (strchr("*()\\", *p) != NULL) {
	    if ( q + 3 >= filtbuf_end) {
		break;
	    }
	    *q++ = '\\';
	    switch ( *p++ )
	    {
	    case '*':
		*q++ = '2';
		*q++ = 'a';
		break;
	    case '(':
		*q++ = '2';
		*q++ = '8';
		break;
	    case ')':
		*q++ = '2';
		*q++ = '9';
		break;
	    case '\\':
		*q++ = '5';
		*q++ = 'c';
		break;
	    }
	}
	else {
	    *q++ = *p++;
	}
    }
#else
    for (p = user, q=filtbuf + strlen(filtbuf);
	 *p && q < filtbuf_end; *q++ = *p++) {
	if (strchr("*()\\", *p) != NULL) {
	    *q++ = '\\';
	    if (q >= filtbuf_end) {
		break;
	    }
	}
    }
#endif
    *q = '\0';

    if (q + 2 <= filtbuf_end) {
	strcat(filtbuf, "))");
    }
}

static int
translate_userdir_ldap(request_rec *r)
{
    userdir_ldap_config_t *sec;
    util_ldap_connection_t *ldc;
    const char *userdirs;
    char filtbuf[FILTER_LENGTH];
    char **attributes = NULL;
    const char **vals = NULL;
    const char *dn = NULL;
    apr_finfo_t statbuf;
    const char *w, *dname;
    char *name = r->uri;
    int result = 0;

    sec = ap_get_module_config(r->server->module_config,
			       &userdir_ldap_module);
    userdirs = sec->userdir;

    if (name[0] != '/' || name [1] != '~') {
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
	    r->server, "[%" APR_PID_T_FMT "] userdir_ldap: invalid uri: %s",
	    getpid(), r->uri);
	return DECLINED;
    }

    if (userdirs == NULL) {
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
	    r->server, "[%" APR_PID_T_FMT "] userdir_ldap: no userdirs",
	    getpid());
	return DECLINED;
    }

    dname = name + 2;
    w = ap_getword(r->pool, &dname, '/');
    if (dname[-1] == '/') {
	--dname;
    }

    if (w[0] == '\0' || (w[1] == '.' &&
		(w[2] == '\0' || (w[2] == '.' && w[3] == '\0')))) {
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
	    r->server, "[%" APR_PID_T_FMT "] userdir_ldap: invalid username: %s",
	    getpid(), w);
	return DECLINED;
    }

    if (apr_table_get(sec->disabled_users, w) != NULL) {
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
	    r->server, "[%" APR_PID_T_FMT "] userdir_ldap: disabled user: `%s'",
	    getpid(), w);
	return DECLINED;
    }

    if (sec->globally_disabled &&
	    apr_table_get(sec->enabled_users, w) == NULL) {
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
	    r->server, "[%" APR_PID_T_FMT "] userdir_ldap: not enabled user: `%s'",
	    getpid(), w);
	return DECLINED;
    }

    if (!sec->have_ldap_url) {
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
	    r->server, "[%" APR_PID_T_FMT "] userdir_ldap: no ldap url",
	    getpid());
	return DECLINED;
    }

    if (sec->host) {
	ldc = util_ldap_connection_find(r, sec->host, sec->port, sec->binddn,
					sec->bindpw, sec->deref, sec->secure);
    } else {
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
	    r->server, "[%" APR_PID_T_FMT "] userdir_ldap: no ldap host",
	    getpid());
	return DECLINED;
    }

    userdir_ldap_build_filter(filtbuf, r, w, sec);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
	r->server, "[%" APR_PID_T_FMT "] userdir_ldap: filter: %s",
	getpid(), filtbuf);

    attributes = apr_pcalloc(r->pool, sizeof(char *) * 2);
    attributes[0] = sec->homeattr ? sec->homeattr : USERDIR_LDAP_DEF_HOME;

    result = util_ldap_cache_getuserdn(r, ldc, sec->url, sec->basedn,
				       sec->scope, attributes,
				       filtbuf, &dn, &vals);
    util_ldap_connection_close(ldc);

    if (result != LDAP_SUCCESS) {
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
	    r->server, "[%" APR_PID_T_FMT "] userdir_ldap: error: 0x%x",
	    getpid(), result);
	return DECLINED;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
	r->server, "[%" APR_PID_T_FMT "] userdir_ldap: home directory: %s %s",
	getpid(), w, vals[0]);

    while (*userdirs) {
	const char *userdir = ap_getword_conf(r->pool, &userdirs);
	char *filename;
	apr_status_t rv;

	filename = (char *)apr_pstrcat(r->pool, vals[0], "/", userdir, NULL);

	if (filename && (!*userdirs || ((rv = apr_stat(&statbuf, filename,
				APR_FINFO_MIN, r->pool)) == APR_SUCCESS ||
			rv == APR_INCOMPLETE))) {
	    r->filename = apr_pstrcat(r->pool, filename, dname, NULL);

	    if (*userdirs && dname[0] == 0) {
		r->finfo = statbuf;
	    }

	    apr_table_setn(r->notes, "mod_userdir_ldap_user", w);

	    return OK;
	}
    }

    return DECLINED;
}

static const char *
set_user_dir(cmd_parms *cmd, void *dummy, const char *arg)
{
    userdir_ldap_config_t *sec =
	ap_get_module_config(cmd->server->module_config, &userdir_ldap_module);

    char *username;
    const char *usernames = arg;
    char *kw = ap_getword_conf(cmd->pool, &usernames);
    apr_table_t *usertable;

    if (*kw == '\0') {
	return "UserDir requires an argument";
    }

    if ((!strcasecmp(kw, "disable")) || (!strcasecmp(kw, "disabled"))) {
	if (strlen(usernames) == 0) {
	    sec->globally_disabled = 1;
	    return NULL;
	}
	usertable = sec->disabled_users;
    }
    else if ((!strcasecmp(kw, "enable")) || (!strcasecmp(kw, "enabled"))) {
	if (strlen(usernames) == 0) {
	    return "UserDir \"enable\" keyword requires a list of usernames";
	}
	usertable = sec->enabled_users;
    }
    else {
	sec->userdir = apr_pstrdup(cmd->pool, arg);
	return NULL;
    }

    while (*usernames) {
	username = ap_getword_conf(cmd->pool, &usernames);
	apr_table_setn(usertable, username, kw);
    }

    return NULL;
}

static const char *
userdir_ldap_parse_url(cmd_parms *cmd,
		    void *dummy,
		    const char *url,
		    const char *mode)
{
    apr_ldap_url_desc_t *urld;
    apr_ldap_err_t *result;
    int rc;

    userdir_ldap_config_t *sec =
	ap_get_module_config(cmd->server->module_config, &userdir_ldap_module);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
	cmd->server, "[%" APR_PID_T_FMT "] userdir_ldap url parse: `%s'",
	getpid(), url);

    rc = apr_ldap_url_parse(cmd->pool, url, &(urld), &(result));
    if (rc != APR_SUCCESS) {
	return result->reason;
    }
    sec->url = apr_pstrdup(cmd->pool, url);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
	cmd->server, "[%" APR_PID_T_FMT "] userdir_ldap url parse: Host: %s",
	getpid(), urld->lud_host);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
	cmd->server, "[%" APR_PID_T_FMT "] userdir_ldap url parse: Port: %d",
	getpid(), urld->lud_port);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
	cmd->server, "[%" APR_PID_T_FMT "] userdir_ldap url parse: DN: %s",
	getpid(), urld->lud_dn);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
	cmd->server, "[%" APR_PID_T_FMT "] userdir_ldap url parse: attrib: %s",
	getpid(), urld->lud_attrs? urld->lud_attrs[0] : "(null)");
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
	cmd->server, "[%" APR_PID_T_FMT "] userdir_ldap url parse: scope: %s",
	getpid(),
	(urld->lud_scope == LDAP_SCOPE_SUBTREE? "subtree" :
	urld->lud_scope == LDAP_SCOPE_BASE? "base" :
	urld->lud_scope == LDAP_SCOPE_ONELEVEL? "onelevel" : "unknown"));
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0,
	cmd->server, "[%" APR_PID_T_FMT "] userdir_ldap url parse: filter: %s",
	getpid(), urld->lud_filter);

    if (sec->host) {
	char *p = apr_palloc(cmd->pool,
			     strlen(sec->host) + strlen(urld->lud_host) + 2);
	strcpy(p, urld->lud_host);
	strcat(p, " ");
	strcat(p, sec->host);
	sec->host = p;
    }
    else {
	sec->host = urld->lud_host?
	    apr_pstrdup(cmd->pool, urld->lud_host) : "localhost";
    }

    sec->basedn = urld->lud_dn? apr_pstrdup(cmd->pool, urld->lud_dn) : "";

    if (urld->lud_attrs && urld->lud_attrs[0]) {
	sec->attribute = urld->lud_attrs[0];
    }

    sec->scope = urld->lud_scope == LDAP_SCOPE_ONELEVEL ?
	LDAP_SCOPE_ONELEVEL : LDAP_SCOPE_SUBTREE;

    if (urld->lud_filter) {
	if (urld->lud_filter[0] == '(') {
	    sec->filter = apr_pstrdup(cmd->pool, urld->lud_filter + 1);
	    sec->filter[strlen(sec->filter) - 1] = '\0';
	}
	else {
	    sec->filter = apr_pstrdup(cmd->pool, urld->lud_filter);
	}
    }

    if (mode) {
	if (strcasecmp("NONE", mode)) {
	    sec->secure = APR_LDAP_NONE;
	}
	else if (strcasecmp("SSL", mode)) {
	    sec->secure = APR_LDAP_SSL;
	}
	else if (strcasecmp("TLS", mode) == 0 ||
		 strcasecmp("STARTTLS", mode) == 0) {
	    sec->secure = APR_LDAP_STARTTLS;
	}
	else {
	    return "Invalid LDAP connection mode setting: must be one of NONE, "
		   "SSL, or TLS/STARTTLS";
	}
    }

    if (strncasecmp(url, "ldaps", 5) == 0) {
	sec->secure = APR_LDAP_SSL;
	sec->port = urld->lud_port? urld->lud_port : LDAPS_PORT;
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
		     "LDAP: userdir_ldap using SSL connections");
    }
    else {
	sec->port = urld->lud_port? urld->lud_port : LDAP_PORT;
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
		     "LDAP: userdir_ldap not using SSL connections");
    }

    sec->have_ldap_url = 1;

    return NULL;
}

static const char *
userdir_ldap_set_deref(cmd_parms *cmd, void *dummy, const char *arg)
{
    userdir_ldap_config_t *sec =
	ap_get_module_config(cmd->server->module_config, &userdir_ldap_module);

    if (strcmp(arg, "never") == 0 || strcasecmp(arg, "off") == 0) {
	sec->deref = never;
    }
    else if (strcmp(arg, "searching") == 0) {
	sec->deref = searching;
    }
    else if (strcmp(arg, "finding") == 0) {
	sec->deref = finding;
    }
    else if (strcmp(arg, "always") == 0) {
	sec->deref = always;
    }
    else {
	return "Unrecognized value for UserDirLDAPAliasDereference directive";
    }

    return NULL;
}

static const char *
userdir_ldap_set_string_slot(cmd_parms *cmd, void *dummy, const char *arg)
{
    userdir_ldap_config_t *sec =
	ap_get_module_config(cmd->server->module_config, &userdir_ldap_module);

    int offset = (int)(long)cmd->info;
    *(const char **)((char *)sec + offset) = arg;
    return NULL;
}

static const command_rec userdir_ldap_cmds[] = {
    AP_INIT_RAW_ARGS("UserDir", set_user_dir, NULL, RSRC_CONF,
	"the public subdirectory in users' home directories, or "
	"'disabled', or 'disabled username username...', or "
	"'enabled username username...'"),
    AP_INIT_TAKE12("UserDirLDAPURL", userdir_ldap_parse_url, NULL, RSRC_CONF,
	"URL to define LDAP connection. This should be an RFC 2255 complaint\n"
	"URL of the form ldap://host[:port]/basedn[?attr[?scope[?filter]]]].\n"
	"<ul>\n"
	"<li>Host is the name of the LDAP server. Use a space separated list of hosts \n"
	"to specify redundant servers.\n"
	"<li>Port is optional, and specifies the port to connect to.\n"
	"<li>basedn specifies the base DN to start searches from\n"
	"<li>Attribute specifies what attribute to search for user ID. "
	"If not provided, it defaults to <b>uid</b>.\n"
	"<li>Scope is the scope of the search, and can be either <b>sub</b> or "
	"<b>one</b>. If not provided, the default is <b>sub</b>.\n"
	"<li>Filter is a filter to use in the search. If not provided, "
	"defaults to <b>(objectClass=*)</b>.\n"
	"</ul>\n"
	"Searches are performed using the attribute and the filter combined. "
	"For example, assume that the\n"
	"LDAP URL is <b>ldap://ldap.airius.com/ou=People, o=Airius?uid?sub?(posixid=*)</b>. "
	"Searches will\n"
	"be done using the filter <b>(&((posixid=*))(uid=<i>username</i>))</b>, "
	"where <i>username</i>\n"
	"is the user name passed by the HTTP client. The search will be a subtree "
	"search on the branch <b>ou=People, o=Airius</b>."),
    AP_INIT_TAKE1("UserDirLDAPDirAttribute", userdir_ldap_set_string_slot,
	(void *)APR_OFFSETOF(userdir_ldap_config_t, homeattr), RSRC_CONF,
	"Attribute name to search for home directory path. "
	"If not provided, it defaults to <b>homeDirectory</b>.\n"),
    AP_INIT_TAKE1("UserDirLDAPBindDN", userdir_ldap_set_string_slot,
	(void *)APR_OFFSETOF(userdir_ldap_config_t, binddn), RSRC_CONF,
	"DN to use to bind to LDAP server. If not provided, "
	"will do an anonymous bind."),
    AP_INIT_TAKE1("UserDirLDAPBindPW", userdir_ldap_set_string_slot,
	(void *)APR_OFFSETOF(userdir_ldap_config_t, bindpw), RSRC_CONF,
	"Password to use to bind to LDAP server. If not provided, "
	"will do an anonymous bind."),
    AP_INIT_TAKE1("UserDirLDAPDereferenceAliases", userdir_ldap_set_deref,
	NULL, RSRC_CONF,
	"Determines how aliases are handled during a search. Can be one of the"
	"values \"never\", \"searching\", \"finding\", or \"always\". "
	"Defaults to always."),
    {NULL}
};

static void
ImportULDAPOptFn (void)
{
    util_ldap_connection_find  =
	APR_RETRIEVE_OPTIONAL_FN(uldap_connection_find);
    util_ldap_cache_getuserdn =
	APR_RETRIEVE_OPTIONAL_FN(uldap_cache_getuserdn);
    util_ldap_connection_close =
	APR_RETRIEVE_OPTIONAL_FN(uldap_connection_close);
}

static void
userdir_ldap_register_hooks(apr_pool_t *p)
{
    static const char * const  pre[] = { "mod_alias.c",       NULL };
    static const char * const succ[] = { "mod_vhost_alias.c", "mod_userdir.c", NULL };

    ap_hook_translate_name(translate_userdir_ldap,pre,succ,APR_HOOK_MIDDLE);
    ap_hook_optional_fn_retrieve(ImportULDAPOptFn, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA userdir_ldap_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,			/* create per-dir    config structures */
    NULL,			/* merge  per-dir    config structures */
    create_userdir_ldap_config,	/* create per-server config structures */
    NULL,			/* merge  per-server config structures */
    userdir_ldap_cmds,		/* table of config file commands       */
    userdir_ldap_register_hooks	/* register hooks                      */
};
