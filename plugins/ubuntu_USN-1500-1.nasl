#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1500-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59903);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/27 14:21:16 $");

  script_cve_id("CVE-2011-4601", "CVE-2011-4602", "CVE-2011-4603", "CVE-2011-4922", "CVE-2011-4939", "CVE-2012-1178", "CVE-2012-2214", "CVE-2012-2318", "CVE-2012-3374");
  script_bugtraq_id(46307, 51010, 51070, 51074, 52475, 52476, 53400, 53706, 54322);
  script_osvdb_id(72798, 77749, 77750, 77751, 80145, 80146, 81707, 81708, 83605);
  script_xref(name:"USN", value:"1500-1");

  script_name(english:"Ubuntu 10.04 LTS / 11.04 / 11.10 / 12.04 LTS : pidgin vulnerabilities (USN-1500-1)");
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
"Evgeny Boger discovered that Pidgin incorrectly handled buddy list
messages in the AIM and ICQ protocol handlers. A remote attacker could
send a specially crafted message and cause Pidgin to crash, leading to
a denial of service. This issue only affected Ubuntu 10.04 LTS, 11.04
and 11.10. (CVE-2011-4601)

Thijs Alkemade discovered that Pidgin incorrectly handled malformed
voice and video chat requests in the XMPP protocol handler. A remote
attacker could send a specially crafted message and cause Pidgin to
crash, leading to a denial of service. This issue only affected Ubuntu
10.04 LTS, 11.04 and 11.10. (CVE-2011-4602)

Diego Bauche Madero discovered that Pidgin incorrectly handled UTF-8
sequences in the SILC protocol handler. A remote attacker could send a
specially crafted message and cause Pidgin to crash, leading to a
denial of service. This issue only affected Ubuntu 10.04 LTS, 11.04
and 11.10. (CVE-2011-4603)

Julia Lawall discovered that Pidgin incorrectly cleared memory
contents used in cryptographic operations. An attacker could exploit
this to read the memory contents, leading to an information
disclosure. This issue only affected Ubuntu 10.04 LTS. (CVE-2011-4922)

Clemens Huebner and Kevin Stange discovered that Pidgin incorrectly
handled nickname changes inside chat rooms in the XMPP protocol
handler. A remote attacker could exploit this by changing nicknames,
leading to a denial of service. This issue only affected Ubuntu 11.10.
(CVE-2011-4939)

Thijs Alkemade discovered that Pidgin incorrectly handled off-line
instant messages in the MSN protocol handler. A remote attacker could
send a specially crafted message and cause Pidgin to crash, leading to
a denial of service. This issue only affected Ubuntu 10.04 LTS, 11.04
and 11.10. (CVE-2012-1178)

Jose Valentin Gutierrez discovered that Pidgin incorrectly handled
SOCKS5 proxy connections during file transfer requests in the XMPP
protocol handler. A remote attacker could send a specially crafted
request and cause Pidgin to crash, leading to a denial of service.
This issue only affected Ubuntu 12.04 LTS and 11.10. (CVE-2012-2214)

Fabian Yamaguchi discovered that Pidgin incorrectly handled malformed
messages in the MSN protocol handler. A remote attacker could send a
specially crafted message and cause Pidgin to crash, leading to a
denial of service. (CVE-2012-2318)

Ulf Harnhammar discovered that Pidgin incorrectly handled messages
with in-line images in the MXit protocol handler. A remote attacker
could send a specially crafted message and possibly execute arbitrary
code with user privileges. (CVE-2012-3374).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected finch, libpurple0 and / or pidgin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpurple0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/10");
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

if (ubuntu_check(osver:"10.04", pkgname:"finch", pkgver:"1:2.6.6-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libpurple0", pkgver:"1:2.6.6-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"pidgin", pkgver:"1:2.6.6-1ubuntu4.5")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"finch", pkgver:"1:2.7.11-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"libpurple0", pkgver:"1:2.7.11-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"pidgin", pkgver:"1:2.7.11-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"finch", pkgver:"1:2.10.0-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"libpurple0", pkgver:"1:2.10.0-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"pidgin", pkgver:"1:2.10.0-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"finch", pkgver:"1:2.10.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libpurple0", pkgver:"1:2.10.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"pidgin", pkgver:"1:2.10.3-0ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "finch / libpurple0 / pidgin");
}
