#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-850-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42207);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2009-0755", "CVE-2009-3603", "CVE-2009-3604", "CVE-2009-3605", "CVE-2009-3607", "CVE-2009-3608", "CVE-2009-3609");
  script_bugtraq_id(36703);
  script_osvdb_id(59143, 59177, 59178, 59179, 59180, 59183, 59825);
  script_xref(name:"USN", value:"850-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 / 9.04 : poppler vulnerabilities (USN-850-1)");
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
"It was discovered that poppler contained multiple security issues when
parsing malformed PDF documents. If a user or automated system were
tricked into opening a crafted PDF file, an attacker could cause a
denial of service or execute arbitrary code with privileges of the
user invoking the program.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-glib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-glib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-glib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-glib4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-qt-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-qt2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-qt4-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-qt4-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler-qt4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler1-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler1-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpoppler4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:poppler-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:poppler-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|8\.04|8\.10|9\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 8.10 / 9.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libpoppler-dev", pkgver:"0.5.1-0ubuntu7.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpoppler-glib-dev", pkgver:"0.5.1-0ubuntu7.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpoppler-qt-dev", pkgver:"0.5.1-0ubuntu7.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpoppler1", pkgver:"0.5.1-0ubuntu7.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpoppler1-glib", pkgver:"0.5.1-0ubuntu7.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libpoppler1-qt", pkgver:"0.5.1-0ubuntu7.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"poppler-utils", pkgver:"0.5.1-0ubuntu7.6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpoppler-dev", pkgver:"0.6.4-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpoppler-glib-dev", pkgver:"0.6.4-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpoppler-glib2", pkgver:"0.6.4-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpoppler-qt-dev", pkgver:"0.6.4-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpoppler-qt2", pkgver:"0.6.4-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpoppler-qt4-2", pkgver:"0.6.4-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpoppler-qt4-dev", pkgver:"0.6.4-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libpoppler2", pkgver:"0.6.4-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"poppler-utils", pkgver:"0.6.4-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libpoppler-dev", pkgver:"0.8.7-1ubuntu0.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libpoppler-glib-dev", pkgver:"0.8.7-1ubuntu0.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libpoppler-glib3", pkgver:"0.8.7-1ubuntu0.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libpoppler-qt-dev", pkgver:"0.8.7-1ubuntu0.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libpoppler-qt2", pkgver:"0.8.7-1ubuntu0.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libpoppler-qt4-3", pkgver:"0.8.7-1ubuntu0.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libpoppler-qt4-dev", pkgver:"0.8.7-1ubuntu0.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libpoppler3", pkgver:"0.8.7-1ubuntu0.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"poppler-dbg", pkgver:"0.8.7-1ubuntu0.4")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"poppler-utils", pkgver:"0.8.7-1ubuntu0.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpoppler-dev", pkgver:"0.10.5-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpoppler-glib-dev", pkgver:"0.10.5-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpoppler-glib4", pkgver:"0.10.5-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpoppler-qt-dev", pkgver:"0.10.5-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpoppler-qt2", pkgver:"0.10.5-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpoppler-qt4-3", pkgver:"0.10.5-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpoppler-qt4-dev", pkgver:"0.10.5-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libpoppler4", pkgver:"0.10.5-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"poppler-dbg", pkgver:"0.10.5-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"poppler-utils", pkgver:"0.10.5-1ubuntu2.4")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpoppler-dev / libpoppler-glib-dev / libpoppler-glib2 / etc");
}
