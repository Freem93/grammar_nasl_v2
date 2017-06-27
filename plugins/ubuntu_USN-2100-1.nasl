#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2100-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72386);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/25 16:34:54 $");

  script_cve_id("CVE-2012-6152", "CVE-2013-6477", "CVE-2013-6478", "CVE-2013-6479", "CVE-2013-6481", "CVE-2013-6482", "CVE-2013-6483", "CVE-2013-6484", "CVE-2013-6485", "CVE-2013-6487", "CVE-2013-6489", "CVE-2013-6490", "CVE-2014-0020");
  script_bugtraq_id(65188, 65192, 65195, 65243, 65492);
  script_xref(name:"USN", value:"2100-1");

  script_name(english:"Ubuntu 12.04 LTS / 12.10 / 13.10 : pidgin vulnerabilities (USN-2100-1)");
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
"Thijs Alkemade and Robert Vehse discovered that Pidgin incorrectly
handled the Yahoo! protocol. A remote attacker could use this issue to
cause Pidgin to crash, resulting in a denial of service.
(CVE-2012-6152)

Jaime Breva Ribes discovered that Pidgin incorrectly handled the XMPP
protocol. A remote attacker could use this issue to cause Pidgin to
crash, resulting in a denial of service. (CVE-2013-6477)

It was discovered that Pidgin incorrecly handled long URLs. A remote
attacker could use this issue to cause Pidgin to crash, resulting in a
denial of service. (CVE-2013-6478)

Jacob Appelbaum discovered that Pidgin incorrectly handled certain
HTTP responses. A malicious remote server or a man in the middle could
use this issue to cause Pidgin to crash, resulting in a denial of
service. (CVE-2013-6479)

Daniel Atallah discovered that Pidgin incorrectly handled the Yahoo!
protocol. A remote attacker could use this issue to cause Pidgin to
crash, resulting in a denial of service. (CVE-2013-6481)

Fabian Yamaguchi and Christian Wressnegger discovered that Pidgin
incorrectly handled the MSN protocol. A remote attacker could use this
issue to cause Pidgin to crash, resulting in a denial of service.
(CVE-2013-6482)

Fabian Yamaguchi and Christian Wressnegger discovered that Pidgin
incorrectly handled XMPP iq replies. A remote attacker could use this
issue to spoof messages. (CVE-2013-6483)

It was discovered that Pidgin incorrectly handled STUN server
responses. A remote attacker could use this issue to cause Pidgin to
crash, resulting in a denial of service. (CVE-2013-6484)

Matt Jones discovered that Pidgin incorrectly handled certain chunked
HTTP responses. A malicious remote server or a man in the middle could
use this issue to cause Pidgin to crash, resulting in a denial of
service, or possibly execute arbitrary code. (CVE-2013-6485)

Yves Younan and Ryan Pentney discovered that Pidgin incorrectly
handled certain Gadu-Gadu HTTP messages. A malicious remote server or
a man in the middle could use this issue to cause Pidgin to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2013-6487)

Yves Younan and Pawel Janic discovered that Pidgin incorrectly handled
MXit emoticons. A remote attacker could use this issue to cause Pidgin
to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2013-6489)

Yves Younan discovered that Pidgin incorrectly handled SIMPLE headers.
A remote attacker could use this issue to cause Pidgin to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2013-6490)

Daniel Atallah discovered that Pidgin incorrectly handled IRC argument
parsing. A malicious remote server or a man in the middle could use
this issue to cause Pidgin to crash, resulting in a denial of service.
(CVE-2014-0020).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libpurple0 and / or pidgin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpurple0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2016 Canonical, Inc. / NASL script (C) 2014-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|12\.10|13\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 12.10 / 13.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libpurple0", pkgver:"1:2.10.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"pidgin", pkgver:"1:2.10.3-0ubuntu1.4")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"libpurple0", pkgver:"1:2.10.6-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"pidgin", pkgver:"1:2.10.6-0ubuntu2.3")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"libpurple0", pkgver:"1:2.10.7-0ubuntu4.1.13.10.1")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"pidgin", pkgver:"1:2.10.7-0ubuntu4.1.13.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpurple0 / pidgin");
}
