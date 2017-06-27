#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-624-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45473);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/27 14:37:17 $");

  script_cve_id("CVE-2008-2371");
  script_osvdb_id(46690);
  script_xref(name:"USN", value:"624-2");

  script_name(english:"Ubuntu 9.10 : erlang vulnerability (USN-624-2)");
  script_summary(english:"Checks dpkg output for updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Ubuntu host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-624-1 fixed a vulnerability in PCRE. This update provides the
corresponding update for Erlang.

Tavis Ormandy discovered that the PCRE library did not correctly
handle certain in-pattern options. An attacker could cause
applications linked against pcre3 to crash, leading to a denial of
service.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-appmon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-asn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-base-hipe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-common-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-corba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-dialyzer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-docbuilder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-edoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-eunit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-gs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-ic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-inets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-inviso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-megaco");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-mnesia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-observer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-os-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-parsetools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-percept");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-pman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-public-key");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-reltool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-runtime-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-syntax-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-test-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-toolbar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-tv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-typer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-webtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-xmerl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2010-2016 Canonical, Inc. / NASL script (C) 2010-2016 Tenable Network Security, Inc.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! ereg(pattern:"^(9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"9.10", pkgname:"erlang", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-appmon", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-asn1", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-base", pkgver:"1:13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-base-hipe", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-common-test", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-corba", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-crypto", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-debugger", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-dev", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-dialyzer", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-docbuilder", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-edoc", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-et", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-eunit", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-examples", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-gs", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-ic", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-inets", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-inviso", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-megaco", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-mnesia", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-mode", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-nox", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-observer", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-odbc", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-os-mon", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-parsetools", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-percept", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-pman", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-public-key", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-reltool", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-runtime-tools", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-snmp", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-src", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-ssh", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-ssl", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-syntax-tools", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-test-server", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-toolbar", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-tools", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-tv", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-typer", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-webtool", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-x11", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"erlang-xmerl", pkgver:"13.b.1-dfsg-2ubuntu1.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "erlang / erlang-appmon / erlang-asn1 / erlang-base / etc");
}
