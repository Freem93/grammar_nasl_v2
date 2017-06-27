#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-633-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33808);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:37:17 $");

  script_cve_id("CVE-2008-1767", "CVE-2008-2935");
  script_bugtraq_id(29312);
  script_osvdb_id(47544);
  script_xref(name:"USN", value:"633-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.04 / 7.10 / 8.04 LTS : libxslt vulnerabilities (USN-633-1)");
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
"It was discovered that long transformation matches in libxslt could
overflow. If an attacker were able to make an application linked
against libxslt process malicious XSL style sheet input, they could
execute arbitrary code with user privileges or cause the application
to crash, leading to a denial of serivce. (CVE-2008-1767)

Chris Evans discovered that the RC4 processing code in libxslt did not
correctly handle corrupted key information. If a remote attacker were
able to make an application linked against libxslt process malicious
XML input, they could crash the application, leading to a denial of
service. (CVE-2008-2935).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxslt1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxslt1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxslt1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-libxslt1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-libxslt1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-libxslt1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xsltproc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2008-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|7\.04|7\.10|8\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.04 / 7.10 / 8.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libxslt1-dev", pkgver:"1.1.15-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libxslt1.1", pkgver:"1.1.15-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python-libxslt1", pkgver:"1.1.15-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-libxslt1", pkgver:"1.1.15-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xsltproc", pkgver:"1.1.15-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libxslt1-dbg", pkgver:"1.1.20-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libxslt1-dev", pkgver:"1.1.20-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libxslt1.1", pkgver:"1.1.20-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"python-libxslt1", pkgver:"1.1.20-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"python-libxslt1-dbg", pkgver:"1.1.20-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"xsltproc", pkgver:"1.1.20-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxslt1-dbg", pkgver:"1.1.21-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxslt1-dev", pkgver:"1.1.21-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxslt1.1", pkgver:"1.1.21-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"python-libxslt1", pkgver:"1.1.21-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"python-libxslt1-dbg", pkgver:"1.1.21-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"xsltproc", pkgver:"1.1.21-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxslt1-dbg", pkgver:"1.1.22-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxslt1-dev", pkgver:"1.1.22-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxslt1.1", pkgver:"1.1.22-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python-libxslt1", pkgver:"1.1.22-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python-libxslt1-dbg", pkgver:"1.1.22-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"xsltproc", pkgver:"1.1.22-1ubuntu1.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxslt1-dbg / libxslt1-dev / libxslt1.1 / python-libxslt1 / etc");
}
