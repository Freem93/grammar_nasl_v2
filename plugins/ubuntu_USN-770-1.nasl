#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-770-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38686);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/27 14:37:18 $");

  script_cve_id("CVE-2009-1601");
  script_osvdb_id(54524);
  script_xref(name:"USN", value:"770-1");

  script_name(english:"Ubuntu 9.04 : clamav vulnerability (USN-770-1)");
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
"A flaw was discovered in the clamav-milter initscript which caused the
ownership of the current working directory to be changed to the
'clamav' user. This update attempts to repair the incorrect ownership
for standard system directories, but it is recommended that the
following command be performed to report any other directories that
may be affected :

$ sudo find -H / -type d -user clamav \! -group clamav 2>/dev/null

Systems configured to run clamav as a user other than the default
'clamav' user will need to adjust the above command accordingly.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav-freshclam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav-milter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:clamav-testfiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclamav-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libclamav6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/05");
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
if (! ereg(pattern:"^(9\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 9.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"9.04", pkgname:"clamav", pkgver:"0.95.1+dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"clamav-base", pkgver:"0.95.1+dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"clamav-daemon", pkgver:"0.95.1+dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"clamav-dbg", pkgver:"0.95.1+dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"clamav-docs", pkgver:"0.95.1+dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"clamav-freshclam", pkgver:"0.95.1+dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"clamav-milter", pkgver:"0.95.1+dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"clamav-testfiles", pkgver:"0.95.1+dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libclamav-dev", pkgver:"0.95.1+dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libclamav6", pkgver:"0.95.1+dfsg-1ubuntu1.2")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clamav / clamav-base / clamav-daemon / clamav-dbg / clamav-docs / etc");
}
