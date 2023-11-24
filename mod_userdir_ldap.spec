# mod_userdir_ldap
#
# Copyright (C) 2006,2007 DesigNET, INC.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

Summary: Userdir LDAP
Name: mod_userdir_ldap
Version: 0.1
Release: 1
License: Freeware
Group: Development/Tools
Source: mod_userdir_ldap-0.1.tar.gz
Requires: apache2 >= 2.2
Buildroot: %{_tmppath}/%{name}-root

%description
This module allows user-specific directory accessed using "http://example.com/~user" syntax, searching home directory path not from system account information, but from LDAP entries.

%description -l jp
このモジュールは、http://example.com/~user/構文を使って、LDAPサーバの属性で指定したホームディレクトリにアクセスできるようにします。

%prep
%setup -q

%build
rm -rf $RPM_BUILD_ROOT
./configure --with-apxs=/usr/sbin/apxs2
make

%install
make DESTDIR=$RPM_BUILD_ROOT install

%clean
rm -rf $RPM_BUILD_ROOT

%files
%attr(755,root,root) /usr/* 

%changelog
* Fri Oct 12 2007 DesigNET,INC <moduserdirldap-manager@lists.sourceforge.jp>
- Initial build.
