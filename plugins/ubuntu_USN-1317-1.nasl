#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1317-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57436);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/27 14:30:01 $");

  script_cve_id("CVE-2008-3520", "CVE-2008-3522", "CVE-2009-3743", "CVE-2010-4054", "CVE-2011-4516", "CVE-2011-4517");
  script_bugtraq_id(31470, 42640, 43932, 50992);
  script_osvdb_id(49890, 49891, 67708, 69213, 77595, 77596);
  script_xref(name:"USN", value:"1317-1");

  script_name(english:"Ubuntu 8.04 LTS / 10.04 LTS / 10.10 : ghostscript vulnerabilities (USN-1317-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Ghostscript did not correctly handle memory
allocation when parsing certain malformed JPEG-2000 images. If a user
or automated system were tricked into opening a specially crafted
image, an attacker could cause a denial of service and possibly
execute arbitrary code with user privileges. (CVE-2008-3520)

It was discovered that Ghostscript did not correctly handle certain
formatting operations when parsing JPEG-2000 images. If a user or
automated system were tricked into opening a specially crafted image,
an attacker could cause a denial of service and possibly execute
arbitrary code with user privileges. (CVE-2008-3522)

It was discovered that Ghostscript incorrectly handled certain
malformed TrueType fonts. If a user or automated system were tricked
into opening a document containing a specially crafted font, an
attacker could cause a denial of service and possibly execute
arbitrary code with user privileges. This issue only affected Ubuntu
8.04 LTS. (CVE-2009-3743)

It was discovered that Ghostscript incorrectly handled certain
malformed Type 2 fonts. If a user or automated system were tricked
into opening a document containing a specially crafted font, an
attacker could cause a denial of service and possibly execute
arbitrary code with user privileges. This issue only affected Ubuntu
8.04 LTS. (CVE-2010-4054)

Jonathan Foote discovered that Ghostscript incorrectly handled certain
malformed JPEG-2000 image files. If a user or automated system were
tricked into opening a specially crafted JPEG-2000 image file, an
attacker could cause Ghostscript to crash or possibly execute
arbitrary code with user privileges. (CVE-2011-4516, CVE-2011-4517).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libgs8 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgs8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2012-2016 Canonical, Inc. / NASL script (C) 2012-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(8\.04|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"libgs8", pkgver:"8.61.dfsg.1-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libgs8", pkgver:"8.71.dfsg.1-0ubuntu5.4")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libgs8", pkgver:"8.71.dfsg.2-0ubuntu7.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgs8");
}
