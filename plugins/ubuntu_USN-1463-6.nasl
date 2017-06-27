#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1463-6. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59725);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/25 16:19:23 $");

  script_cve_id("CVE-2011-3101", "CVE-2012-0441", "CVE-2012-1937", "CVE-2012-1938", "CVE-2012-1940", "CVE-2012-1941", "CVE-2012-1944", "CVE-2012-1945", "CVE-2012-1946", "CVE-2012-1947");
  script_bugtraq_id(53791, 53793, 53794, 53796, 53798, 53799, 53800, 53801, 53808);
  script_xref(name:"USN", value:"1463-6");

  script_name(english:"Ubuntu 11.04 : thunderbird vulnerabilities (USN-1463-6)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-1463-1 fixed vulnerabilities in Firefox. This update provides the
corresponding fixes for Thunderbird.

Jesse Ruderman, Igor Bukanov, Bill McCloskey, Christian Holler, Andrew
McCreight, Olli Pettay, Boris Zbarsky, and Brian Bondy discovered
memory safety issues affecting Firefox. If the user were tricked into
opening a specially crafted page, an attacker could possibly exploit
these to cause a denial of service via application crash, or
potentially execute code with the privileges of the user invoking
Firefox. (CVE-2012-1937, CVE-2012-1938)

It was discovered that Mozilla's WebGL implementation
exposed a bug in certain NVIDIA graphics drivers. The impact
of this issue has not been disclosed at this time.
(CVE-2011-3101)

Adam Barth discovered that certain inline event handlers
were not being blocked properly by the Content Security
Policy's (CSP) inline-script blocking feature. Web
applications relying on this feature of CSP to protect
against cross-site scripting (XSS) were not fully protected.
With cross-site scripting vulnerabilities, if a user were
tricked into viewing a specially crafted page, a remote
attacker could exploit this to modify the contents, or steal
confidential data, within the same domain. (CVE-2012-1944)

Paul Stone discovered that a viewed HTML page hosted on a
Windows or Samba share could load Windows shortcut files
(.lnk) in the same share. These shortcut files could then
link to arbitrary locations on the local file system of the
individual loading the HTML page. An attacker could
potentially use this vulnerability to show the contents of
these linked files or directories in an iframe, resulting in
information disclosure. (CVE-2012-1945)

Arthur Gerkis discovered a use-after-free vulnerability
while replacing/inserting a node in a document. If the user
were tricked into opening a specially crafted page, an
attacker could possibly exploit this to cause a denial of
service via application crash, or potentially execute code
with the privileges of the user invoking Firefox.
(CVE-2012-1946)

Kaspar Brand discovered a vulnerability in how the Network
Security Services (NSS) ASN.1 decoder handles zero length
items. If the user were tricked into opening a specially
crafted page, an attacker could possibly exploit this to
cause a denial of service via application crash.
(CVE-2012-0441)

Abhishek Arya discovered two buffer overflow and one
use-after-free vulnerabilities. If the user were tricked
into opening a specially crafted page, an attacker could
possibly exploit these to cause a denial of service via
application crash, or potentially execute code with the
privileges of the user invoking Firefox. (CVE-2012-1940,
CVE-2012-1941, CVE-2012-1947).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/27");
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
if (! ereg(pattern:"^(11\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 11.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"11.04", pkgname:"thunderbird", pkgver:"13.0.1+build1-0ubuntu0.11.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
