#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-125-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20515);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/26 16:22:49 $");

  script_cve_id("CVE-2005-0967", "CVE-2005-1261", "CVE-2005-1262");
  script_xref(name:"USN", value:"125-1");

  script_name(english:"Ubuntu 4.10 / 5.04 : gaim vulnerabilities (USN-125-1)");
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
"Marco Alvarez found a Denial of Service vulnerability in the Jabber
protocol handler. A remote attacker could exploit this to crash Gaim
by sending specially crafted file transfers to the user.
(CAN-2005-0967)

Stu Tomlinson discovered an insufficient bounds checking flaw in the
URL parser. By sending a message containing a very long URL, a remote
attacker could crash Gaim or execute arbitrary code with the
privileges of the user. This was not possible on all protocols, due to
message length restrictions. Jabber are SILC were known to be
vulnerable. (CAN-2005-1261)

Siebe Tolsma discovered a Denial of Service attack in the MSN handler.
By sending a specially crafted SLP message with an empty body, a
remote attacker could crash Gaim. (CAN-2005-1262).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gaim, gaim-data and / or gaim-dev packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gaim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gaim-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gaim-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
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
if (! ereg(pattern:"^(4\.10|5\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10 / 5.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"gaim", pkgver:"1.0.0-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gaim", pkgver:"1.1.4-1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gaim-data", pkgver:"1.1.4-1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gaim-dev", pkgver:"1.1.4-1ubuntu4.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gaim / gaim-data / gaim-dev");
}
