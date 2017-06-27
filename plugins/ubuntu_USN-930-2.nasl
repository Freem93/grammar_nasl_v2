#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-930-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47162);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/27 14:45:44 $");

  script_cve_id("CVE-2008-5913", "CVE-2010-1121", "CVE-2010-1125", "CVE-2010-1196", "CVE-2010-1197", "CVE-2010-1198", "CVE-2010-1199", "CVE-2010-1200", "CVE-2010-1201", "CVE-2010-1202", "CVE-2010-1203");
  script_bugtraq_id(33276, 38952, 40701, 41082, 41087, 41090, 41093, 41094, 41099, 41102, 41103);
  script_osvdb_id(63479);
  script_xref(name:"USN", value:"930-2");

  script_name(english:"Ubuntu 8.04 LTS : apturl, epiphany-browser, gecko-sharp, gnome-python-extras, liferea, rhythmbox, totem, ubufox, yelp update (USN-930-2)");
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
"USN-930-1 fixed vulnerabilities in Firefox and Xulrunner. This update
provides updated packages for use with Firefox 3.6 and Xulrunner 1.9.2
on Ubuntu 8.04 LTS.

If was discovered that Firefox could be made to access freed memory.
If a user were tricked into viewing a malicious site, a remote
attacker could cause a denial of service or possibly execute arbitrary
code with the privileges of the user invoking the program. This issue
only affected Ubuntu 8.04 LTS. (CVE-2010-1121)

Several flaws were discovered in the browser engine of
Firefox. If a user were tricked into viewing a malicious
site, a remote attacker could cause a denial of service or
possibly execute arbitrary code with the privileges of the
user invoking the program. (CVE-2010-1200, CVE-2010-1201,
CVE-2010-1202, CVE-2010-1203)

A flaw was discovered in the way plugin instances
interacted. An attacker could potentially exploit this and
use one plugin to access freed memory from a second plugin
to execute arbitrary code with the privileges of the user
invoking the program. (CVE-2010-1198)

An integer overflow was discovered in Firefox. If a user
were tricked into viewing a malicious site, an attacker
could overflow a buffer and cause a denial of service or
possibly execute arbitrary code with the privileges of the
user invoking the program. (CVE-2010-1196)

Martin Barbella discovered an integer overflow in an XSLT
node sorting routine. An attacker could exploit this to
overflow a buffer and cause a denial of service or possibly
execute arbitrary code with the privileges of the user
invoking the program. (CVE-2010-1199)

Michal Zalewski discovered that the focus behavior of
Firefox could be subverted. If a user were tricked into
viewing a malicious site, a remote attacker could use this
to capture keystrokes. (CVE-2010-1125)

Ilja van Sprundel discovered that the 'Content-Disposition:
attachment' HTTP header was ignored when 'Content-Type:
multipart' was also present. Under certain circumstances,
this could potentially lead to cross-site scripting attacks.
(CVE-2010-1197)

Amit Klein discovered that Firefox did not seed its random
number generator often enough. An attacker could exploit
this to identify and track users across different websites.
(CVE-2008-5913).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apturl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:epiphany-browser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:epiphany-browser-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:epiphany-browser-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:epiphany-browser-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:epiphany-gecko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgecko2.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liferea");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liferea-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:monodoc-gecko2.0-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-gnome2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-gnome2-extras-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-gnome2-extras-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-gnome2-extras-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-gtkhtml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-gtkhtml2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rhythmbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rhythmbox-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:totem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:totem-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:totem-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:totem-gstreamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:totem-mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:totem-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:totem-plugins-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:totem-xine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ubufox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2010-2016 Canonical, Inc. / NASL script (C) 2010-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(8\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"apturl", pkgver:"0.2.2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"epiphany-browser", pkgver:"2.22.2-0ubuntu0.8.04.7")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"epiphany-browser-data", pkgver:"2.22.2-0ubuntu0.8.04.7")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"epiphany-browser-dbg", pkgver:"2.22.2-0ubuntu0.8.04.7")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"epiphany-browser-dev", pkgver:"2.22.2-0ubuntu0.8.04.7")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"epiphany-gecko", pkgver:"2.22.2-0ubuntu0.8.04.7")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libgecko2.0-cil", pkgver:"0.11-3ubuntu4.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"liferea", pkgver:"1.4.14-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"liferea-dbg", pkgver:"1.4.14-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"monodoc-gecko2.0-manual", pkgver:"0.11-3ubuntu4.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python-gnome2-extras", pkgver:"2.19.1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python-gnome2-extras-dbg", pkgver:"2.19.1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python-gnome2-extras-dev", pkgver:"2.19.1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python-gnome2-extras-doc", pkgver:"2.19.1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python-gtkhtml2", pkgver:"2.19.1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python-gtkhtml2-dbg", pkgver:"2.19.1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"rhythmbox", pkgver:"0.11.5-0ubuntu8.8.04.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"rhythmbox-dbg", pkgver:"0.11.5-0ubuntu8.8.04.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"totem", pkgver:"2.22.1-0ubuntu3.8.04.6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"totem-common", pkgver:"2.22.1-0ubuntu3.8.04.6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"totem-dbg", pkgver:"2.22.1-0ubuntu3.8.04.6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"totem-gstreamer", pkgver:"2.22.1-0ubuntu3.8.04.6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"totem-mozilla", pkgver:"2.22.1-0ubuntu3.8.04.6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"totem-plugins", pkgver:"2.22.1-0ubuntu3.8.04.6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"totem-plugins-extra", pkgver:"2.22.1-0ubuntu3.8.04.6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"totem-xine", pkgver:"2.22.1-0ubuntu3.8.04.6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ubufox", pkgver:"0.9~rc2-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"yelp", pkgver:"2.22.1-0ubuntu2.8.04.4")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apturl / epiphany-browser / epiphany-browser-data / etc");
}
