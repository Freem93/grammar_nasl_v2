#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-185-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20596);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:21:17 $");

  script_cve_id("CVE-2004-2154");
  script_osvdb_id(17912);
  script_xref(name:"USN", value:"185-1");

  script_name(english:"Ubuntu 4.10 : cupsys vulnerability (USN-185-1)");
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
"A flaw was detected in the printer access control list checking in the
CUPS server. Printer names were compared in a case sensitive manner;
by modifying the capitalization of printer names, a remote attacker
could circumvent ACLs and print to printers he should not have access
to.

The Ubuntu 5.04 version of cupsys is not vulnerable against this.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys-bsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsimage2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsimage2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsys2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsys2-gnutls10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/05/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2005-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"cupsys", pkgver:"1.1.20final+cvs20040330-4ubuntu16.5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"cupsys-bsd", pkgver:"1.1.20final+cvs20040330-4ubuntu16.5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"cupsys-client", pkgver:"1.1.20final+cvs20040330-4ubuntu16.5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libcupsimage2", pkgver:"1.1.20final+cvs20040330-4ubuntu16.5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libcupsimage2-dev", pkgver:"1.1.20final+cvs20040330-4ubuntu16.5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libcupsys2-dev", pkgver:"1.1.20final+cvs20040330-4ubuntu16.5")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libcupsys2-gnutls10", pkgver:"1.1.20final+cvs20040330-4ubuntu16.5")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cupsys / cupsys-bsd / cupsys-client / libcupsimage2 / etc");
}
