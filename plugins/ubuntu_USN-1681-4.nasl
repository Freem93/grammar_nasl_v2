#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1681-4. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64480);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/25 16:19:26 $");

  script_cve_id("CVE-2012-5829", "CVE-2013-0744", "CVE-2013-0745", "CVE-2013-0746", "CVE-2013-0747", "CVE-2013-0748", "CVE-2013-0749", "CVE-2013-0750", "CVE-2013-0752", "CVE-2013-0753", "CVE-2013-0754", "CVE-2013-0755", "CVE-2013-0756", "CVE-2013-0757", "CVE-2013-0758", "CVE-2013-0759", "CVE-2013-0760", "CVE-2013-0761", "CVE-2013-0762", "CVE-2013-0763", "CVE-2013-0764", "CVE-2013-0766", "CVE-2013-0767", "CVE-2013-0768", "CVE-2013-0769", "CVE-2013-0770", "CVE-2013-0771");
  script_xref(name:"USN", value:"1681-4");

  script_name(english:"Ubuntu 10.04 LTS / 11.10 / 12.04 LTS / 12.10 : firefox regression (USN-1681-4)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-1681-1 fixed vulnerabilities in Firefox. Due to an upstream
regression, Firefox suffered from instabilities when accessing some
websites. This update fixes the problem.

We apologize for the inconvenience.

Christoph Diehl, Christian Holler, Mats Palmgren, Chiaki Ishikawa,
Bill Gianopoulos, Benoit Jacob, Gary Kwong, Robert O'Callahan, Jesse
Ruderman, and Julian Seward discovered multiple memory safety issues
affecting Firefox. If the user were tricked into opening a specially
crafted page, an attacker could possibly exploit these to cause a
denial of service via application crash, or potentially execute code
with the privileges of the user invoking Firefox. (CVE-2013-0769,
CVE-2013-0749, CVE-2013-0770)

Abhishek Arya discovered several user-after-free and buffer
overflows in Firefox. An attacker could exploit these to
cause a denial of service via application crash, or
potentially execute code with the privileges of the user
invoking Firefox. (CVE-2013-0760, CVE-2013-0761,
CVE-2013-0762, CVE-2013-0763, CVE-2013-0766, CVE-2013-0767,
CVE-2013-0771, CVE-2012-5829)

A stack buffer was discovered in Firefox. If the user were
tricked into opening a specially crafted page, an attacker
could possibly exploit this to cause a denial of service via
application crash, or potentially execute code with the
privileges of the user invoking Firefox. (CVE-2013-0768)

Masato Kinugawa discovered that Firefox did not always
properly display URL values in the address bar. A remote
attacker could exploit this to conduct URL spoofing and
phishing attacks. (CVE-2013-0759)

Atte Kettunen discovered that Firefox did not properly
handle HTML tables with a large number of columns and column
groups. If the user were tricked into opening a specially
crafted page, an attacker could exploit this to cause a
denial of service via application crash, or potentially
execute code with the privileges of the user invoking
Firefox. (CVE-2013-0744)

Jerry Baker discovered that Firefox did not always properly
handle threading when performing downloads over SSL
connections. An attacker could exploit this to cause a
denial of service via application crash. (CVE-2013-0764)

Olli Pettay and Boris Zbarsky discovered flaws in the
Javacript engine of Firefox. An attacker could cause a
denial of service via application crash, or potentially
execute code with the privileges of the user invoking
Firefox. (CVE-2013-0745, CVE-2013-0746)

Jesse Ruderman discovered a flaw in the way Firefox handled
plugins. If a user were tricked into opening a specially
crafted page, a remote attacker could exploit this to bypass
security protections to conduct clickjacking attacks.
(CVE-2013-0747)

Jesse Ruderman discovered an information leak in Firefox. An
attacker could exploit this to reveal memory address layout
which could help in bypassing ASLR protections.
(CVE-2013-0748)

An integer overflow was discovered in the JavaScript engine,
leading to a heap-based buffer overflow. If the user were
tricked into opening a specially crafted page, an attacker
could possibly exploit this to execute code with the
privileges of the user invoking Firefox. (CVE-2013-0750)

Sviatoslav Chagaev discovered that Firefox did not properly
handle XBL files with multiple XML bindings with SVG
content. An attacker could cause a denial of service via
application crash, or potentially execute code with the
privileges of the user invoking Firefox. (CVE-2013-0752)

Mariusz Mlynski discovered two flaws to gain access to
privileged chrome functions. An attacker could possibly
exploit this to execute code with the privileges of the user
invoking Firefox. (CVE-2013-0757, CVE-2013-0758)

Several use-after-free issues were discovered in Firefox. If
the user were tricked into opening a specially crafted page,
an attacker could possibly exploit this to execute code with
the privileges of the user invoking Firefox. (CVE-2013-0753,
CVE-2013-0754, CVE-2013-0755, CVE-2013-0756)

Two intermediate CA certificates were mis-issued by the
TURKTRUST certificate authority. If a remote attacker were
able to perform a man-in-the-middle attack, this flaw could
be exploited to view sensitive information. (CVE-2013-0743).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox 17.0.1 Flash Privileged Code Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2013-2016 Canonical, Inc. / NASL script (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04|11\.10|12\.04|12\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 11.10 / 12.04 / 12.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"firefox", pkgver:"18.0.2+build1-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"firefox", pkgver:"18.0.2+build1-0ubuntu0.11.10.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"firefox", pkgver:"18.0.2+build1-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"firefox", pkgver:"18.0.2+build1-0ubuntu0.12.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox");
}
