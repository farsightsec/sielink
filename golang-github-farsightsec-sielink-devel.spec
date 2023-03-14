%global provider        github
%global provider_tld    com
%global project         farsightsec
%global repo            sielink
# https://github.com/farsightsec/sielink
%global provider_prefix %{provider}.%{provider_tld}/%{project}/%{repo}
%global import_path     %{provider_prefix}
%global commit          37c18321b34ee3908f87fa1f8ac310874bc04667
%global shortcommit     %(c=%{commit}; echo ${c:0:7})

Name:		golang-github-farsightsec-sielink		
Version:	0.1.1
Release:	1%{?dist}
Summary:	Sielink protocol library

License:	MPLv2.0	
URL:		https://%{provider_prefix}
Source0:	https://%{provider_prefix}/archive/%{commit}/%{repo}-%{shortcommit}.tar.gz

BuildRequires: %{?go_compiler:compiler(go-compiler)}%{!?go_compiler:golang}
BuildRequires: golang(golang.org/x/net/websocket)
BuildRequires: golang(github.com/golang/protobuf/proto)

%description
%{summary}

Package sielink implements the protocol used for communication between SIE sensors and submission servers, as well for coordination between submission servers.

%prep
%setup -q -n %{repo}-%{commit}

%build

# installs source code for building other projects
# find all *.go but no *_test.go files and generate file-list
# and no framestream_dump/main.go
%install
#rm -rf $RPM_BUILD_ROOT
install -d -p %{buildroot}/%{gopath}/src/%{import_path}/
for file in $(find . -iname "*.go" \! -iname "*_test.go" \! -iname "main.go" ) ; do
    echo "%%dir %%{gopath}/src/%%{import_path}/$(dirname $file)" >> file-list
    install -d -p %{buildroot}/%{gopath}/src/%{import_path}/$(dirname $file)
    cp -pav $file %{buildroot}/%{gopath}/src/%{import_path}/$file
    echo "%%{gopath}/src/%%{import_path}/$file" >> file-list
done
sort -u -o file-list file-list

#define license tag if not already defined
%{!?_licensedir:%global license %doc}

%files -f file-list 
%license LICENSE 
%doc README.md
%dir %{gopath}/src/%{provider}.%{provider_tld}/%{project}

%changelog

