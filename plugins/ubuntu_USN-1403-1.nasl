#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1403-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58444);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/25 16:11:46 $");

  script_cve_id("CVE-2012-1126", "CVE-2012-1127", "CVE-2012-1128", "CVE-2012-1129", "CVE-2012-1130", "CVE-2012-1131", "CVE-2012-1132", "CVE-2012-1133", "CVE-2012-1134", "CVE-2012-1135", "CVE-2012-1136", "CVE-2012-1137", "CVE-2012-1138", "CVE-2012-1139", "CVE-2012-1140", "CVE-2012-1141", "CVE-2012-1142", "CVE-2012-1143", "CVE-2012-1144");
  script_bugtraq_id(52318);
  script_osvdb_id(79872, 79873, 79874, 79875, 79876, 79877, 79878, 79880, 79881, 79882, 79883, 79884, 79885, 79886, 79887, 79888, 79889, 79890, 79891);
  script_xref(name:"USN", value:"1403-1");

  script_name(english:"Ubuntu 8.04 LTS / 10.04 LTS / 10.10 / 11.04 / 11.10 : freetype vulnerabilities (USN-1403-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mateusz Jurczyk discovered that FreeType did not correctly handle
certain malformed BDF font files. If a user were tricked into using a
specially crafted font file, a remote attacker could cause FreeType to
crash. (CVE-2012-1126)

Mateusz Jurczyk discovered that FreeType did not correctly handle
certain malformed BDF font files. If a user were tricked into using a
specially crafted font file, a remote attacker could cause FreeType to
crash. (CVE-2012-1127)

Mateusz Jurczyk discovered that FreeType did not correctly handle
certain malformed TrueType font files. If a user were tricked into
using a specially crafted font file, a remote attacker could cause
FreeType to crash. (CVE-2012-1128)

Mateusz Jurczyk discovered that FreeType did not correctly handle
certain malformed Type42 font files. If a user were tricked into using
a specially crafted font file, a remote attacker could cause FreeType
to crash. (CVE-2012-1129)

Mateusz Jurczyk discovered that FreeType did not correctly handle
certain malformed PCF font files. If a user were tricked into using a
specially crafted font file, a remote attacker could cause FreeType to
crash. (CVE-2012-1130)

Mateusz Jurczyk discovered that FreeType did not correctly handle
certain malformed TrueType font files. If a user were tricked into
using a specially crafted font file, a remote attacker could cause
FreeType to crash. (CVE-2012-1131)

Mateusz Jurczyk discovered that FreeType did not correctly handle
certain malformed Type1 font files. If a user were tricked into using
a specially crafted font file, a remote attacker could cause FreeType
to crash. (CVE-2012-1132)

Mateusz Jurczyk discovered that FreeType did not correctly handle
certain malformed BDF font files. If a user were tricked into using a
specially crafted font file, a remote attacker could cause FreeType to
crash or possibly execute arbitrary code with user privileges.
(CVE-2012-1133)

Mateusz Jurczyk discovered that FreeType did not correctly handle
certain malformed Type1 font files. If a user were tricked into using
a specially crafted font file, a remote attacker could cause FreeType
to crash or possibly execute arbitrary code with user privileges.
(CVE-2012-1134)

Mateusz Jurczyk discovered that FreeType did not correctly handle
certain malformed TrueType font files. If a user were tricked into
using a specially crafted font file, a remote attacker could cause
FreeType to crash. (CVE-2012-1135)

Mateusz Jurczyk discovered that FreeType did not correctly handle
certain malformed BDF font files. If a user were tricked into using a
specially crafted font file, a remote attacker could cause FreeType to
crash or possibly execute arbitrary code with user privileges.
(CVE-2012-1136)

Mateusz Jurczyk discovered that FreeType did not correctly handle
certain malformed BDF font files. If a user were tricked into using a
specially crafted font file, a remote attacker could cause FreeType to
crash. (CVE-2012-1137)

Mateusz Jurczyk discovered that FreeType did not correctly handle
certain malformed TrueType font files. If a user were tricked into
using a specially crafted font file, a remote attacker could cause
FreeType to crash. (CVE-2012-1138)

Mateusz Jurczyk discovered that FreeType did not correctly handle
certain malformed BDF font files. If a user were tricked into using a
specially crafted font file, a remote attacker could cause FreeType to
crash. (CVE-2012-1139)

Mateusz Jurczyk discovered that FreeType did not correctly handle
certain malformed PostScript font files. If a user were tricked into
using a specially crafted font file, a remote attacker could cause
FreeType to crash. (CVE-2012-1140)

Mateusz Jurczyk discovered that FreeType did not correctly handle
certain malformed BDF font files. If a user were tricked into using a
specially crafted font file, a remote attacker could cause FreeType to
crash. (CVE-2012-1141)

Mateusz Jurczyk discovered that FreeType did not correctly handle
certain malformed Windows FNT/FON font files. If a user were tricked
into using a specially crafted font file, a remote attacker could
cause FreeType to crash. (CVE-2012-1142)

Mateusz Jurczyk discovered that FreeType did not correctly handle
certain malformed font files. If a user were tricked into using a
specially crafted font file, a remote attacker could cause FreeType to
crash. (CVE-2012-1143)

Mateusz Jurczyk discovered that FreeType did not correctly handle
certain malformed TrueType font files. If a user were tricked into
using a specially crafted font file, a remote attacker could cause
FreeType to crash or possibly execute arbitrary code with user
privileges. (CVE-2012-1144).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libfreetype6 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreetype6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/23");
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
if (! ereg(pattern:"^(8\.04|10\.04|10\.10|11\.04|11\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 10.04 / 10.10 / 11.04 / 11.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"libfreetype6", pkgver:"2.3.5-1ubuntu4.8.04.9")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libfreetype6", pkgver:"2.3.11-1ubuntu2.6")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libfreetype6", pkgver:"2.4.2-2ubuntu0.4")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"libfreetype6", pkgver:"2.4.4-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"libfreetype6", pkgver:"2.4.4-2ubuntu1.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libfreetype6");
}
