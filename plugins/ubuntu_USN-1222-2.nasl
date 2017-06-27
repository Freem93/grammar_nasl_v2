#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1222-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56387);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/26 16:14:09 $");

  script_cve_id("CVE-2011-2372", "CVE-2011-2995", "CVE-2011-2997", "CVE-2011-2999", "CVE-2011-3000", "CVE-2011-3001", "CVE-2011-3002", "CVE-2011-3003", "CVE-2011-3005", "CVE-2011-3232");
  script_bugtraq_id(49808, 49810, 49811, 49812, 49813, 49837, 49847, 49848, 49849, 49850);
  script_xref(name:"USN", value:"1222-2");

  script_name(english:"Ubuntu 11.04 : mozvoikko, ubufox, webfav update (USN-1222-2)");
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
"USN-1222-1 fixed vulnerabilities in Firefox. This update provides
updated packages for use with Firefox 7.

Benjamin Smedberg, Bob Clary, Jesse Ruderman, Bob Clary, Andrew
McCreight, Andreas Gal, Gary Kwong, Igor Bukanov, Jason Orendorff,
Jesse Ruderman, and Marcia Knous discovered multiple memory
vulnerabilities in the browser rendering engine. An attacker could use
these to possibly execute arbitrary code with the privileges of the
user invoking Firefox. (CVE-2011-2995, CVE-2011-2997)

Boris Zbarsky discovered that a frame named 'location' could
shadow the window.location object unless a script in a page
grabbed a reference to the true object before the frame was
created. This is in violation of the Same Origin Policy. A
malicious website could possibly use this to access another
website or the local file system. (CVE-2011-2999)

Ian Graham discovered that when multiple Location headers
were present, Firefox would use the second one resulting in
a possible CRLF injection attack. CRLF injection issues can
result in a wide variety of attacks, such as XSS (Cross-Site
Scripting) vulnerabilities, browser cache poisoning, and
cookie theft. (CVE-2011-3000)

Mariusz Mlynski discovered that if the user could be
convinced to hold down the enter key, a malicious website
could potential pop up a download dialog and the default
open action would be selected or lead to the installation of
an arbitrary add-on. This would result in potentially
malicious content being run with privileges of the user
invoking Firefox. (CVE-2011-2372, CVE-2011-3001)

Michael Jordon and Ben Hawkes discovered flaws in WebGL. If
a user were tricked into opening a malicious page, an
attacker could cause the browser to crash. (CVE-2011-3002,
CVE-2011-3003)

It was discovered that Firefox did not properly free memory
when processing ogg files. If a user were tricked into
opening a malicious page, an attacker could cause the
browser to crash. (CVE-2011-3005)

David Rees and Aki Helin discovered a problems in the
JavaScript engine. An attacker could exploit this to crash
the browser or potentially escalate privileges within the
browser. (CVE-2011-3232).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected xul-ext-mozvoikko, xul-ext-ubufox and / or
xul-ext-webfav packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xul-ext-mozvoikko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xul-ext-ubufox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xul-ext-webfav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2016 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"11.04", pkgname:"xul-ext-mozvoikko", pkgver:"1.10.0-0ubuntu0.11.04.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"xul-ext-ubufox", pkgver:"0.9.2-0ubuntu0.11.04.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"xul-ext-webfav", pkgver:"1.17-0ubuntu5.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xul-ext-mozvoikko / xul-ext-ubufox / xul-ext-webfav");
}
