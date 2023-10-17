%global debug_package %{nil}

# https://github.com/farsightsec/sielink
%global goipath         github.com/farsightsec/sielink
Version:                0.1.1

%gometa

%global common_description %{expand:
Implements the protocol used for communication between SIE sensors and submission servers, as well for coordination between submission servers.}

%global golicenses      LICENSE
%global godocs          README.md

Name:           %{goname}
Release:        %autorelease
Summary:        Sielink protocol library

License:        MPLv2.0
URL:            %{gourl}
Source0:        %{gosource}

%description
%{common_description}

%gopkg

%prep
%goprep

%generate_buildrequires
%go_generate_buildrequires

%install
%gopkginstall

%if %{with check}
%check
%gocheck
%endif

%gopkgfiles

%changelog
%autochangelog
