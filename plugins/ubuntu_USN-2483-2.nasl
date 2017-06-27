#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2483-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81018);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/24 17:37:08 $");

  script_cve_id("CVE-2014-8137", "CVE-2014-8138", "CVE-2014-8157", "CVE-2014-8158");
  script_bugtraq_id(71742, 71746, 72293, 72296);
  script_osvdb_id(116027, 116028, 117408, 117409);
  script_xref(name:"USN", value:"2483-2");

  script_name(english:"Ubuntu 10.04 LTS : ghostscript vulnerabilities (USN-2483-2)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-2483-1 fixed vulnerabilities in JasPer. This update provides the
corresponding fix for the JasPer library embedded in the Ghostscript
package.

Jose Duart discovered that JasPer incorrectly handled ICC color
profiles in JPEG-2000 image files. If a user were tricked into opening
a specially crafted JPEG-2000 image file, a remote attacker could
cause JasPer to crash or possibly execute arbitrary code with user
privileges. (CVE-2014-8137)

Jose Duart discovered that JasPer incorrectly decoded
certain malformed JPEG-2000 image files. If a user were
tricked into opening a specially crafted JPEG-2000 image
file, a remote attacker could cause JasPer to crash or
possibly execute arbitrary code with user privileges.
(CVE-2014-8138)

It was discovered that JasPer incorrectly handled certain
malformed JPEG-2000 image files. If a user were tricked into
opening a specially crafted JPEG-2000 image file, a remote
attacker could cause JasPer to crash or possibly execute
arbitrary code with user privileges. (CVE-2014-8157)

It was discovered that JasPer incorrectly handled memory
when processing JPEG-2000 image files. If a user were
tricked into opening a specially crafted JPEG-2000 image
file, a remote attacker could cause JasPer to crash or
possibly execute arbitrary code with user privileges.
(CVE-2014-8158).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libgs8 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgs8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2015-2016 Canonical, Inc. / NASL script (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"libgs8", pkgver:"8.71.dfsg.1-0ubuntu5.7")) flag++;

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
