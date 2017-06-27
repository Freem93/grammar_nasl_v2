#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-312-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27887);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:21:17 $");

  script_cve_id("CVE-2006-3404");
  script_bugtraq_id(18877);
  script_osvdb_id(27037);
  script_xref(name:"USN", value:"312-1");

  script_name(english:"Ubuntu 5.04 / 5.10 / 6.06 LTS : gimp vulnerability (USN-312-1)");
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
"Henning Makholm discovered that gimp did not sufficiently validate the
'num_axes' parameter in XCF files. By tricking a user into opening a
specially crafted XCF file with Gimp, an attacker could exploit this
to execute arbitrary code with the user's privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gimp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gimp-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gimp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gimp-helpbrowser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gimp-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gimp-svg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gimp1.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgimp2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgimp2.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgimp2.0-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2006-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5\.04|5\.10|6\.06)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.04 / 5.10 / 6.06", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.04", pkgname:"gimp", pkgver:"2.2.2-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gimp-data", pkgver:"2.2.2-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gimp-helpbrowser", pkgver:"2.2.2-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gimp-python", pkgver:"2.2.2-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gimp-svg", pkgver:"2.2.2-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gimp1.2", pkgver:"2.2.2-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libgimp2.0", pkgver:"2.2.2-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libgimp2.0-dev", pkgver:"2.2.2-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libgimp2.0-doc", pkgver:"2.2.2-1ubuntu5.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"gimp", pkgver:"2.2.8-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"gimp-data", pkgver:"2.2.8-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"gimp-helpbrowser", pkgver:"2.2.8-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"gimp-python", pkgver:"2.2.8-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"gimp-svg", pkgver:"2.2.8-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"gimp1.2", pkgver:"2.2.8-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libgimp2.0", pkgver:"2.2.8-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libgimp2.0-dev", pkgver:"2.2.8-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libgimp2.0-doc", pkgver:"2.2.8-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"gimp", pkgver:"2.2.11-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"gimp-data", pkgver:"2.2.11-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"gimp-dbg", pkgver:"2.2.11-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"gimp-helpbrowser", pkgver:"2.2.11-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"gimp-python", pkgver:"2.2.11-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"gimp-svg", pkgver:"2.2.11-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgimp2.0", pkgver:"2.2.11-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgimp2.0-dev", pkgver:"2.2.11-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgimp2.0-doc", pkgver:"2.2.11-1ubuntu3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gimp / gimp-data / gimp-dbg / gimp-helpbrowser / gimp-python / etc");
}
