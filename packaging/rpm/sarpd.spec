%define prefix /usr/local

Summary:    sarpd is a daemon for Secure-ARP authentication
Name:       sarpd
Version:    0.0.9-devel
Release:    @RELEASE@
Serial:     @SERIAL@
Packager:   ALoR <alor@users.sourceforge.net>
Source:     http://sarpd.sourceforge.net/download/%{name}-%{version}.tar.gz
URL:        http://sarpd.sourceforge.net/
License:    GPL
Group:      Networking/Daemons
Prefix:     %{prefix}
Buildroot:  %{_tmppath}/%{name}-%{version}-root

%description
sarpd is a daemon for Secure-ARP authentication 

%prep
%setup -q

%build
./configure --prefix=%{prefix} --disable-debug --mandir=%{_mandir}
make

rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%{_mandir}/man8/*
%doc COPYING README CHANGELOG AUTHOR TODO THANKS INSTALL 
%{prefix}/bin/*
