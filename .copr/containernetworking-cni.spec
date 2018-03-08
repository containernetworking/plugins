%if 0%{?fedora}
%global with_devel 1
%global with_bundled 1
%global with_debug 0
%global with_check 0
%global with_unit_test 1
%else 
%global with_devel 0
%global with_bundled 1
%global with_debug 0
%global with_check 0
%global with_unit_test 0
%endif

%if 0%{?with_debug}
%global _dwz_low_mem_die_limit 0
%else
%global debug_package   %{nil}
%endif

%if ! 0%{?gobuild:1}
%define gobuild(o:) go build -ldflags "${LDFLAGS:-} -B 0x$(head -c20 /dev/urandom|od -An -tx1|tr -d ' \\n')" -a -v -x %{?**};
%endif

%global provider        github
%global provider_tld    com
%global project         containernetworking
%global repo            plugins
# https://github.com/containernetworking/cni
%global provider_prefix %{provider}.%{provider_tld}/%{project}/%{repo}
%global import_path     %{provider_prefix}
%global commit          7480240de9749f9a0a5c8614b17f1f03e0c06ab9
%global shortcommit     %(c=%{commit}; echo ${c:0:7})

Name:           containernetworking-cni
Version:        0.6.0
Release:        3%{?dist}
Summary:        Libraries for writing CNI plugin
License:        ASL 2.0
URL:            https://%{provider_prefix}
Source0:        https://%{provider_prefix}/%{version}.tar.gz

ExcludeArch:    ppc64
# If go_compiler is not set to 1, there is no virtual provide. Use golang instead.
BuildRequires:  %{?go_compiler:compiler(go-compiler)}%{!?go_compiler:golang}


%if ! 0%{?with_bundled}
BuildRequires: go-md2man
BuildRequires: go-bindata
BuildRequires: golang(github.com/vishvananda/netlink)
BuildRequires: golang(github.com/coreos/go-systemd/activation)
BuildRequires: golang(github.com/d2g/dhcp4)
BuildRequires: golang(github.com/d2g/dhcp4client)
BuildRequires: golang(github.com/vishvananda/netlink)
BuildRequires: golang(golang.org/x/sys/unix)
BuildRequires: golang(github.com/coreos/go-iptables/iptables)
%endif

Provides: containernetworking-plugins = %{version}-%{release}

%description
The CNI (Container Network Interface) project consists of a specification
and libraries for writing plugins to configure network interfaces in Linux
containers, along with a number of supported plugins. CNI concerns itself
only with network connectivity of containers and removing allocated resources
when the container is deleted.

%if 0%{?with_devel}
%package devel
Summary:       %{summary}
BuildArch:     noarch

%if 0%{?with_check} && ! 0%{?with_bundled}
BuildRequires: golang(github.com/coreos/go-iptables/iptables)
BuildRequires: golang(github.com/vishvananda/netlink)
BuildRequires: golang(golang.org/x/sys/unix)
%endif

Requires:      golang(github.com/coreos/go-iptables/iptables)
Requires:      golang(github.com/vishvananda/netlink)
Requires:      golang(golang.org/x/sys/unix)

Provides:      golang(%{import_path}/libcni) = %{version}-%{release}
Provides:      golang(%{import_path}/pkg/invoke) = %{version}-%{release}
Provides:      golang(%{import_path}/pkg/invoke/fakes) = %{version}-%{release}
Provides:      golang(%{import_path}/pkg/ip) = %{version}-%{release}
Provides:      golang(%{import_path}/pkg/ipam) = %{version}-%{release}
Provides:      golang(%{import_path}/pkg/ns) = %{version}-%{release}
Provides:      golang(%{import_path}/pkg/skel) = %{version}-%{release}
Provides:      golang(%{import_path}/pkg/testutils) = %{version}-%{release}
Provides:      golang(%{import_path}/pkg/types) = %{version}-%{release}
Provides:      golang(%{import_path}/pkg/types/020) = %{version}-%{release}
Provides:      golang(%{import_path}/pkg/types/current) = %{version}-%{release}
Provides:      golang(%{import_path}/pkg/utils) = %{version}-%{release}
Provides:      golang(%{import_path}/pkg/utils/hwaddr) = %{version}-%{release}
Provides:      golang(%{import_path}/pkg/utils/sysctl) = %{version}-%{release}
Provides:      golang(%{import_path}/pkg/version) = %{version}-%{release}
Provides:      golang(%{import_path}/pkg/version/legacy_examples) = %{version}-%{release}
Provides:      golang(%{import_path}/pkg/version/testhelpers) = %{version}-%{release}
Provides:      golang(%{import_path}/plugins/ipam/host-local/backend) = %{version}-%{release}
Provides:      golang(%{import_path}/plugins/ipam/host-local/backend/allocator) = %{version}-%{release}
Provides:      golang(%{import_path}/plugins/ipam/host-local/backend/disk) = %{version}-%{release}
Provides:      golang(%{import_path}/plugins/ipam/host-local/backend/testing) = %{version}-%{release}
Provides:      golang(%{import_path}/plugins/test/noop/debug) = %{version}-%{release}

%description devel
This package contains library source intended for
building other packages which use import path with
%{import_path} prefix.
%endif

%if 0%{?with_unit_test} && 0%{?with_devel}
%package unit-test-devel
Summary:         Unit tests for %{name} package
%if 0%{?with_check}
%endif

Requires:        %{name}-devel = %{version}-%{release}

%if 0%{?with_check} && ! 0%{?with_bundled}
BuildRequires: golang(github.com/d2g/dhcp4)
BuildRequires: golang(github.com/onsi/ginkgo)
BuildRequires: golang(github.com/onsi/ginkgo/config)
BuildRequires: golang(github.com/onsi/ginkgo/extensions/table)
BuildRequires: golang(github.com/onsi/gomega)
BuildRequires: golang(github.com/onsi/gomega/gbytes)
BuildRequires: golang(github.com/onsi/gomega/gexec)
BuildRequires: golang(github.com/vishvananda/netlink/nl)
%endif

Requires:      golang(github.com/d2g/dhcp4)
Requires:      golang(github.com/onsi/ginkgo)
Requires:      golang(github.com/onsi/ginkgo/config)
Requires:      golang(github.com/onsi/ginkgo/extensions/table)
Requires:      golang(github.com/onsi/gomega)
Requires:      golang(github.com/onsi/gomega/gbytes)
Requires:      golang(github.com/onsi/gomega/gexec)
Requires:      golang(github.com/vishvananda/netlink/nl)

%description unit-test-devel
This package contains unit tests for project
providing packages with %{import_path} prefix.
%endif

%prep
%setup -q

%build
./build.sh

%install
install -d -p %{buildroot}%{_libexecdir}/cni/
install -p -m 0755 bin/* %{buildroot}/%{_libexecdir}/cni

# source codes for building projects
%if 0%{?with_devel}
install -d -p %{buildroot}/%{gopath}/src/%{import_path}/
echo "%%dir %%{gopath}/src/%%{import_path}/." >> devel.file-list
# find all *.go but no *_test.go files and generate devel.file-list
for file in $(find . \( -iname "*.go" -or -iname "*.s" \) \! -iname "*_test.go" | grep -v "vendor") ; do
    dirprefix=$(dirname $file)
    install -d -p %{buildroot}/%{gopath}/src/%{import_path}/$dirprefix
    cp -pav $file %{buildroot}/%{gopath}/src/%{import_path}/$file
    echo "%%{gopath}/src/%%{import_path}/$file" >> devel.file-list

    while [ "$dirprefix" != "." ]; do
        echo "%%dir %%{gopath}/src/%%{import_path}/$dirprefix" >> devel.file-list
        dirprefix=$(dirname $dirprefix)
    done
done
%endif

# testing files for this project
%if 0%{?with_unit_test} && 0%{?with_devel}
install -d -p %{buildroot}/%{gopath}/src/%{import_path}/
# find all *_test.go files and generate unit-test-devel.file-list
for file in $(find . -iname "*_test.go" | grep -v "vendor") ; do
    dirprefix=$(dirname $file)
    install -d -p %{buildroot}/%{gopath}/src/%{import_path}/$dirprefix
    cp -pav $file %{buildroot}/%{gopath}/src/%{import_path}/$file
    echo "%%{gopath}/src/%%{import_path}/$file" >> unit-test-devel.file-list

    while [ "$dirprefix" != "." ]; do
        echo "%%dir %%{gopath}/src/%%{import_path}/$dirprefix" >> devel.file-list
        dirprefix=$(dirname $dirprefix)
    done
done
%endif

%if 0%{?with_devel}
sort -u -o devel.file-list devel.file-list
%endif

%check
%if 0%{?with_check} && 0%{?with_unit_test} && 0%{?with_devel}
%if ! 0%{?with_bundled}
export GOPATH=%{buildroot}/%{gopath}:%{gopath}
%else
# Since we aren't packaging up the vendor directory we need to link
# back to it somehow. Hack it up so that we can add the vendor
# directory from BUILD dir as a gopath to be searched when executing
# tests from the BUILDROOT dir.
ln -s ./ ./vendor/src # ./vendor/src -> ./vendor

export GOPATH=%{buildroot}/%{gopath}:$(pwd)/vendor:%{gopath}
%endif

%if ! 0%{?gotest:1}
%global gotest go test
%endif

%gotest %{import_path}/libcni
%gotest %{import_path}/pkg/invoke
%gotest %{import_path}/pkg/ip
%gotest %{import_path}/pkg/ipam
%gotest %{import_path}/pkg/ns
%gotest %{import_path}/pkg/skel
%gotest %{import_path}/pkg/types
%gotest %{import_path}/pkg/types/020
%gotest %{import_path}/pkg/types/current
%gotest %{import_path}/pkg/utils
%gotest %{import_path}/pkg/utils/hwaddr
%gotest %{import_path}/pkg/version
%gotest %{import_path}/pkg/version/legacy_examples
%gotest %{import_path}/pkg/version/testhelpers
%gotest %{import_path}/plugins/ipam/dhcp
%gotest %{import_path}/plugins/ipam/host-local
%gotest %{import_path}/plugins/ipam/host-local/backend/allocator
%gotest %{import_path}/plugins/main/bridge
%gotest %{import_path}/plugins/main/ipvlan
%gotest %{import_path}/plugins/main/loopback
%gotest %{import_path}/plugins/main/macvlan
%gotest %{import_path}/plugins/main/ptp
%gotest %{import_path}/plugins/meta/flannel
%gotest %{import_path}/plugins/test/noop
%endif

#define license tag if not already defined
%{!?_licensedir:%global license %doc}

%files
%license LICENSE
%doc *.md
%{_libexecdir}/cni/*

%if 0%{?with_devel}
%files devel -f devel.file-list
%license LICENSE
%doc *.md
%dir %{gopath}/src/%{provider}.%{provider_tld}/%{project}
%endif

%if 0%{?with_unit_test} && 0%{?with_devel}
%files unit-test-devel -f unit-test-devel.file-list
%license LICENSE
%doc *.md
%endif

%changelog
* Wed Feb 07 2018 Fedora Release Engineering <releng@fedoraproject.org> - 0.6.0-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_28_Mass_Rebuild

* Tue Jan 23 2018 Dan Williams <dcbw@redhat.com> - 0.6.0-2
- skip settling IPv4 addresses

* Mon Jan 08 2018 Frantisek Kluknavsky <fkluknav@redhat.com> - 0.6.0-1
- rebased to 7480240de9749f9a0a5c8614b17f1f03e0c06ab9

* Fri Oct 13 2017 Lokesh Mandvekar <lsm5@fedoraproject.org> - 0.5.2-7
- do not install to /opt (against Fedora Guidelines)

* Thu Aug 24 2017 Jan Chaloupka <jchaloup@redhat.com> - 0.5.2-6
- Enable devel subpackage

* Wed Aug 02 2017 Fedora Release Engineering <releng@fedoraproject.org> - 0.5.2-5
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Binutils_Mass_Rebuild

* Wed Jul 26 2017 Fedora Release Engineering <releng@fedoraproject.org> - 0.5.2-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Mass_Rebuild

* Thu Jul 13 2017 Lokesh Mandvekar <lsm5@fedoraproject.org> - 0.5.2-3
- excludearch: ppc64 as it's not in goarches anymore
- re-enable s390x

* Fri Jun 30 2017 Lokesh Mandvekar <lsm5@fedoraproject.org> - 0.5.2-2
- upstream moved to github.com/containernetworking/plugins
- built commit dcf7368
- provides: containernetworking-plugins
- use vendored deps because they're a lot less of a PITA
- excludearch: s390x for now (rhbz#1466865)

* Mon Jun 12 2017 Timothy St. Clair <tstclair@heptio.com> - 0.5.2-1
- Update to 0.5.2 
- Softlink to default /opt/cni/bin directories

* Sun May 07 2017 Timothy St. Clair <tstclair@heptio.com> - 0.5.1-1
- Initial package

