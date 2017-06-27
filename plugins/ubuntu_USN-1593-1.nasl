#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1593-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62411);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/25 16:19:25 $");

  script_cve_id("CVE-2012-0212", "CVE-2012-2240", "CVE-2012-2241", "CVE-2012-2242", "CVE-2012-3500");
  script_bugtraq_id(52029, 55358, 55564);
  script_osvdb_id(79321, 85610, 85611, 85612, 85613);
  script_xref(name:"USN", value:"1593-1");

  script_name(english:"Ubuntu 10.04 LTS / 11.04 / 11.10 / 12.04 LTS : devscripts vulnerabilities (USN-1593-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Raphael Geissert discovered that the debdiff.pl tool incorrectly
handled shell metacharacters. If a user or automated system were
tricked into processing a specially crafted filename, a remote
attacker could possibly execute arbitrary code. (CVE-2012-0212)

Raphael Geissert discovered that the dscverify tool incorrectly
escaped arguments to external commands. If a user or automated system
were tricked into processing specially crafted files, a remote
attacker could possibly execute arbitrary code. (CVE-2012-2240)

Raphael Geissert discovered that the dget tool incorrectly performed
input validation. If a user or automated system were tricked into
processing specially crafted files, a remote attacker could delete
arbitrary files. (CVE-2012-2241)

Raphael Geissert discovered that the dget tool incorrectly escaped
arguments to external commands. If a user or automated system were
tricked into processing specially crafted files, a remote attacker
could possibly execute arbitrary code. This issue only affected Ubuntu
10.04 LTS and Ubuntu 11.04. (CVE-2012-2242)

Jim Meyering discovered that the annotate-output tool incorrectly
handled temporary files. A local attacker could use this flaw to alter
files being processed by the annotate-output tool. On Ubuntu 11.04 and
later, this issue was mitigated by the Yama kernel symlink
restrictions. (CVE-2012-3500).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected devscripts package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:devscripts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/03");
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
if (! ereg(pattern:"^(10\.04|11\.04|11\.10|12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 11.04 / 11.10 / 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"devscripts", pkgver:"2.10.61ubuntu5.3")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"devscripts", pkgver:"2.10.69ubuntu2.2")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"devscripts", pkgver:"2.11.1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"devscripts", pkgver:"2.11.6ubuntu1.4")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "devscripts");
}
