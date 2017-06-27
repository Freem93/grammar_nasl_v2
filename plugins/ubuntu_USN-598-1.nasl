#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-598-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31785);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/27 14:29:19 $");

  script_cve_id("CVE-2008-0047", "CVE-2008-0053", "CVE-2008-0882", "CVE-2008-1373");
  script_bugtraq_id(27906, 28307, 28334, 28544);
  script_osvdb_id(43376, 44160);
  script_xref(name:"USN", value:"598-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 / 7.10 : cupsys vulnerabilities (USN-598-1)");
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
"It was discovered that the CUPS administration interface contained a
heap- based overflow flaw. A local attacker, and a remote attacker if
printer sharing is enabled, could send a malicious request and
possibly execute arbitrary code as the non-root user in Ubuntu 6.06
LTS, 6.10, and 7.04. In Ubuntu 7.10, attackers would be isolated by
the AppArmor CUPS profile. (CVE-2008-0047)

It was discovered that the hpgl filter in CUPS did not properly
validate its input when parsing parameters. If a crafted HP-GL/2 file
were printed, an attacker could possibly execute arbitrary code as the
non-root user in Ubuntu 6.06 LTS, 6.10, and 7.04. In Ubuntu 7.10,
attackers would be isolated by the AppArmor CUPS profile.
(CVE-2008-0053)

It was discovered that CUPS had a flaw in its managing of remote
shared printers via IPP. A remote attacker could send a crafted UDP
packet and cause a denial of service or possibly execute arbitrary
code as the non-root user in Ubuntu 6.06 LTS, 6.10, and 7.04. In
Ubuntu 7.10, attackers would be isolated by the AppArmor CUPS profile.
(CVE-2008-0882)

It was discovered that CUPS did not properly perform bounds checking
in its GIF decoding routines. If a crafted GIF file were printed, an
attacker could possibly execute arbitrary code as the non-root user in
Ubuntu 6.06 LTS, 6.10, and 7.04. In Ubuntu 7.10, attackers would be
isolated by the AppArmor CUPS profile. (CVE-2008-1373).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys-bsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsimage2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsimage2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsys2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsys2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsys2-gnutls10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/04");
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
if (! ereg(pattern:"^(6\.06|6\.10|7\.04|7\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 6.10 / 7.04 / 7.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"cupsys", pkgver:"1.2.2-0ubuntu0.6.06.8")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"cupsys-bsd", pkgver:"1.2.2-0ubuntu0.6.06.8")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"cupsys-client", pkgver:"1.2.2-0ubuntu0.6.06.8")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsimage2", pkgver:"1.2.2-0ubuntu0.6.06.8")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsimage2-dev", pkgver:"1.2.2-0ubuntu0.6.06.8")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsys2", pkgver:"1.2.2-0ubuntu0.6.06.8")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsys2-dev", pkgver:"1.2.2-0ubuntu0.6.06.8")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcupsys2-gnutls10", pkgver:"1.2.2-0ubuntu0.6.06.8")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"cupsys", pkgver:"1.2.4-2ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"cupsys-bsd", pkgver:"1.2.4-2ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"cupsys-client", pkgver:"1.2.4-2ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"cupsys-common", pkgver:"1.2.4-2ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libcupsimage2", pkgver:"1.2.4-2ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libcupsimage2-dev", pkgver:"1.2.4-2ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libcupsys2", pkgver:"1.2.4-2ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libcupsys2-dev", pkgver:"1.2.4-2ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"cupsys", pkgver:"1.2.8-0ubuntu8.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"cupsys-bsd", pkgver:"1.2.8-0ubuntu8.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"cupsys-client", pkgver:"1.2.8-0ubuntu8.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"cupsys-common", pkgver:"1.2.8-0ubuntu8.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libcupsimage2", pkgver:"1.2.8-0ubuntu8.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libcupsimage2-dev", pkgver:"1.2.8-0ubuntu8.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libcupsys2", pkgver:"1.2.8-0ubuntu8.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libcupsys2-dev", pkgver:"1.2.8-0ubuntu8.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"cupsys", pkgver:"1.3.2-1ubuntu7.6")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"cupsys-bsd", pkgver:"1.3.2-1ubuntu7.6")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"cupsys-client", pkgver:"1.3.2-1ubuntu7.6")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"cupsys-common", pkgver:"1.3.2-1ubuntu7.6")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcupsimage2", pkgver:"1.3.2-1ubuntu7.6")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcupsimage2-dev", pkgver:"1.3.2-1ubuntu7.6")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcupsys2", pkgver:"1.3.2-1ubuntu7.6")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcupsys2-dev", pkgver:"1.3.2-1ubuntu7.6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cupsys / cupsys-bsd / cupsys-client / cupsys-common / libcupsimage2 / etc");
}
