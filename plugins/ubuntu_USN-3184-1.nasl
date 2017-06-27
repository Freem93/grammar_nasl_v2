#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3184-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96953);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/03/13 15:28:56 $");

  script_cve_id("CVE-2016-7553", "CVE-2017-5193", "CVE-2017-5194", "CVE-2017-5195", "CVE-2017-5196", "CVE-2017-5356");
  script_osvdb_id(144868, 149651, 149652, 149653, 149654, 150083);
  script_xref(name:"USN", value:"3184-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 16.04 LTS / 16.10 : irssi vulnerabilities (USN-3184-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the Irssi buf.pl script set incorrect
permissions. A local attacker could use this issue to retrieve another
user's window contents. (CVE-2016-7553)

Joseph Bisch discovered that Irssi incorrectly handled comparing
nicks. A remote attacker could use this issue to cause Irssi to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2017-5193)

It was discovered that Irssi incorrectly handled invalid nick
messages. A remote attacker could use this issue to cause Irssi to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2017-5194)

Joseph Bisch discovered that Irssi incorrectly handled certain
incomplete control codes. A remote attacker could use this issue to
cause Irssi to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 16.04 LTS and
Ubuntu 16.10. (CVE-2017-5195)

Hanno Bock and Joseph Bisch discovered that Irssi incorrectly handled
certain incomplete character sequences. A remote attacker could use
this issue to cause Irssi to crash, resulting in a denial of service.
This issue only affected Ubuntu 16.04 LTS and Ubuntu 16.10.
(CVE-2017-5196)

Hanno Bock discovered that Irssi incorrectly handled certain format
strings. A remote attacker could use this issue to cause Irssi to
crash, resulting in a denial of service. (CVE-2017-5356).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected irssi package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:irssi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2017 Canonical, Inc. / NASL script (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|16\.04|16\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 16.04 / 16.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"irssi", pkgver:"0.8.15-4ubuntu3.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"irssi", pkgver:"0.8.15-5ubuntu3.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"irssi", pkgver:"0.8.19-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"irssi", pkgver:"0.8.19-1ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "irssi");
}
