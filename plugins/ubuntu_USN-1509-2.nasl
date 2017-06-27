#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1509-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60013);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:21:16 $");

  script_cve_id("CVE-2012-1948", "CVE-2012-1949", "CVE-2012-1950", "CVE-2012-1951", "CVE-2012-1952", "CVE-2012-1953", "CVE-2012-1954", "CVE-2012-1955", "CVE-2012-1957", "CVE-2012-1958", "CVE-2012-1959", "CVE-2012-1960", "CVE-2012-1961", "CVE-2012-1962", "CVE-2012-1963", "CVE-2012-1964", "CVE-2012-1965", "CVE-2012-1966", "CVE-2012-1967");
  script_bugtraq_id(54572, 54573, 54574, 54575, 54576, 54577, 54578, 54579, 54580, 54581, 54583, 54584, 54585, 54586);
  script_osvdb_id(83995, 83996, 83997, 83998, 83999, 84000, 84001, 84002, 84003, 84004, 84005, 84006, 84007, 84008, 84009, 84010, 84011, 84012, 84013);
  script_xref(name:"USN", value:"1509-2");

  script_name(english:"Ubuntu 10.04 LTS / 11.04 / 11.10 / 12.04 LTS : ubufox update (USN-1509-2)");
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
"USN-1509-1 fixed vulnerabilities in Firefox. This update provides an
updated ubufox package for use with the lastest Firefox.

Benoit Jacob, Jesse Ruderman, Christian Holler, Bill McCloskey, Brian
Smith, Gary Kwong, Christoph Diehl, Chris Jones, Brad Lassey, and Kyle
Huey discovered memory safety issues affecting Firefox. If the user
were tricked into opening a specially crafted page, an attacker could
possibly exploit these to cause a denial of service via application
crash, or potentially execute code with the privileges of the user
invoking Firefox. (CVE-2012-1948, CVE-2012-1949)

Mario Gomes discovered that the address bar may be
incorrectly updated. Drag-and-drop events in the address bar
may cause the address of the previous site to be displayed
while a new page is loaded. An attacker could exploit this
to conduct phishing attacks. (CVE-2012-1950)

Abhishek Arya discovered four memory safety issues affecting
Firefox. If the user were tricked into opening a specially
crafted page, an attacker could possibly exploit these to
cause a denial of service via application crash, or
potentially execute code with the privileges of the user
invoking Firefox. (CVE-2012-1951, CVE-2012-1952,
CVE-2012-1953, CVE-2012-1954)

Mariusz Mlynski discovered that the address bar may be
incorrectly updated. Calls to history.forward and
history.back could be used to navigate to a site while the
address bar still displayed the previous site. A remote
attacker could exploit this to conduct phishing attacks.
(CVE-2012-1955)

Mario Heiderich discovered that HTML <embed> tags were not
filtered out of the HTML <description> of RSS feeds. A
remote attacker could exploit this to conduct cross-site
scripting (XSS) attacks via JavaScript execution in the HTML
feed view. (CVE-2012-1957)

Arthur Gerkis discovered a use-after-free vulnerability. If
the user were tricked into opening a specially crafted page,
an attacker could possibly exploit this to cause a denial of
service via application crash, or potentially execute code
with the privileges of the user invoking Firefox.
(CVE-2012-1958)

Bobby Holley discovered that same-compartment security
wrappers (SCSW) could be bypassed to allow XBL access. If
the user were tricked into opening a specially crafted page,
an attacker could possibly exploit this to execute code with
the privileges of the user invoking Firefox. (CVE-2012-1959)

Tony Payne discovered an out-of-bounds memory read in
Mozilla's color management library (QCMS). If the user were
tricked into opening a specially crafted color profile, an
attacker could possibly exploit this to cause a denial of
service via application crash. (CVE-2012-1960)

Frederic Buclin discovered that the X-Frame-Options header
was ignored when its value was specified multiple times. An
attacker could exploit this to conduct clickjacking attacks.
(CVE-2012-1961)

Bill Keese discovered a memory corruption vulnerability. If
the user were tricked into opening a specially crafted page,
an attacker could possibly exploit this to cause a denial of
service via application crash, or potentially execute code
with the privileges of the user invoking Firefox.
(CVE-2012-1962)

Karthikeyan Bhargavan discovered an information leakage
vulnerability in the Content Security Policy (CSP) 1.0
implementation. If the user were tricked into opening a
specially crafted page, an attacker could possibly exploit
this to access a user's OAuth 2.0 access tokens and OpenID
credentials. (CVE-2012-1963)

Matt McCutchen discovered a clickjacking vulnerability in
the certificate warning page. A remote attacker could trick
a user into accepting a malicious certificate via a crafted
certificate warning page. (CVE-2012-1964)

Mario Gomes and Soroush Dalili discovered that JavaScript
was not filtered out of feed URLs. If the user were tricked
into opening a specially crafted URL, an attacker could
possibly exploit this to conduct cross-site scripting (XSS)
attacks. (CVE-2012-1965)

A vulnerability was discovered in the context menu of data:
URLs. If the user were tricked into opening a specially
crafted URL, an attacker could possibly exploit this to
conduct cross-site scripting (XSS) attacks. (CVE-2012-1966)

It was discovered that the execution of javascript: URLs was
not properly handled in some cases. A remote attacker could
exploit this to execute code with the privileges of the user
invoking Firefox. (CVE-2012-1967).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ubufox and / or xul-ext-ubufox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ubufox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xul-ext-ubufox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/18");
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

if (ubuntu_check(osver:"10.04", pkgname:"ubufox", pkgver:"2.1.1-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"xul-ext-ubufox", pkgver:"2.1.1-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"ubufox", pkgver:"2.1.1-0ubuntu0.11.04.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"xul-ext-ubufox", pkgver:"2.1.1-0ubuntu0.11.04.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"ubufox", pkgver:"2.1.1-0ubuntu0.11.10.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"xul-ext-ubufox", pkgver:"2.1.1-0ubuntu0.11.10.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"ubufox", pkgver:"2.1.1-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"xul-ext-ubufox", pkgver:"2.1.1-0ubuntu0.12.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ubufox / xul-ext-ubufox");
}
