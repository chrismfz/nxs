Name:           nxs
Version:        2026.05.04
Release:        1%{?dist}
Summary:        iNtegrity eXploit Scanner for Linux hosting servers
License:        MIT
URL:            https://github.com/chrismfz/nxs
BuildArch:      x86_64
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
Requires(pre): shadow-utils

%description
NXS is a host security scanner for shared Linux/cPanel hosting servers.

%pre
if ! getent group nxs >/dev/null 2>&1; then
    groupadd --system nxs
fi

if ! getent passwd nxs >/dev/null 2>&1; then
    useradd \
        --system \
        --gid nxs \
        --no-create-home \
        --home-dir /var/lib/nxs \
        --shell /sbin/nologin \
        -c "NXS service account" \
        nxs
fi

%prep
# nothing

%build
# nothing

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}

if [ -d "%{pkgroot}/usr" ]; then
  cp -a "%{pkgroot}/usr" "%{buildroot}/"
fi
if [ -d "%{pkgroot}/etc" ]; then
  cp -a "%{pkgroot}/etc" "%{buildroot}/"
fi

if [ -f "%{buildroot}/lib/systemd/system/nxs.service" ]; then
  mkdir -p "%{buildroot}%{_unitdir}"
  mv "%{buildroot}/lib/systemd/system/nxs.service" "%{buildroot}%{_unitdir}/"
  rm -rf "%{buildroot}/lib/systemd"
fi

install -Dm644 %{projectroot}/LICENSE %{buildroot}/usr/share/licenses/nxs/LICENSE

%files
%license /usr/share/licenses/nxs/LICENSE
%{_bindir}/nxs
%{_unitdir}/nxs.service
%config(noreplace) /etc/nxs/nxs.conf
%dir %{_datadir}/nxs
%dir %{_datadir}/nxs/configs
%{_datadir}/nxs/configs/*

%post
systemctl daemon-reload || true
systemctl enable nxs.service || true
systemctl restart nxs.service || true

%preun
%systemd_preun nxs.service

%postun
%systemd_postun_with_restart nxs.service
