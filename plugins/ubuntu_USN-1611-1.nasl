#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1611-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62548);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/25 16:19:25 $");

  script_cve_id("CVE-2012-3982", "CVE-2012-3983", "CVE-2012-3984", "CVE-2012-3985", "CVE-2012-3986", "CVE-2012-3988", "CVE-2012-3989", "CVE-2012-3990", "CVE-2012-3991", "CVE-2012-3992", "CVE-2012-3993", "CVE-2012-3994", "CVE-2012-3995", "CVE-2012-4179", "CVE-2012-4180", "CVE-2012-4181", "CVE-2012-4182", "CVE-2012-4183", "CVE-2012-4184", "CVE-2012-4185", "CVE-2012-4186", "CVE-2012-4187", "CVE-2012-4188", "CVE-2012-4191", "CVE-2012-4192", "CVE-2012-4193");
  script_bugtraq_id(55856, 55889);
  script_osvdb_id(86094, 86095, 86096, 86097, 86098, 86099, 86100, 86101, 86102, 86103, 86104, 86105, 86106, 86108, 86109, 86110, 86111, 86112, 86113, 86114, 86115, 86116, 86117, 86125, 86126, 86128);
  script_xref(name:"USN", value:"1611-1");

  script_name(english:"Ubuntu 10.04 LTS / 11.04 / 11.10 / 12.04 LTS : thunderbird vulnerabilities (USN-1611-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Henrik Skupin, Jesse Ruderman, Christian Holler, Soroush Dalili and
others discovered several memory corruption flaws in Thunderbird. If a
user were tricked into opening a malicious website and had JavaScript
enabled, an attacker could exploit these to execute arbitrary
JavaScript code within the context of another website or arbitrary
code as the user invoking the program. (CVE-2012-3982, CVE-2012-3983,
CVE-2012-3988, CVE-2012-3989, CVE-2012-4191)

David Bloom and Jordi Chancel discovered that Thunderbird did not
always properly handle the <select> element. If a user were tricked
into opening a malicious website and had JavaScript enabled, a remote
attacker could exploit this to conduct URL spoofing and clickjacking
attacks. (CVE-2012-3984)

Collin Jackson discovered that Thunderbird did not properly follow the
HTML5 specification for document.domain behavior. If a user were
tricked into opening a malicious website and had JavaScript enabled, a
remote attacker could exploit this to conduct cross-site scripting
(XSS) attacks via JavaScript execution. (CVE-2012-3985)

Johnny Stenback discovered that Thunderbird did not properly perform
security checks on test methods for DOMWindowUtils. (CVE-2012-3986)

Alice White discovered that the security checks for GetProperty could
be bypassed when using JSAPI. If a user were tricked into opening a
specially crafted web page and had JavaScript enabled, a remote
attacker could exploit this to execute arbitrary code as the user
invoking the program. (CVE-2012-3991)

Mariusz Mlynski discovered a history state error in Thunderbird. If a
user were tricked into opening a malicious website and had JavaScript
enabled, a remote attacker could exploit this to spoof the location
property to inject script or intercept posted data. (CVE-2012-3992)

Mariusz Mlynski and others discovered several flaws in Thunderbird
that allowed a remote attacker to conduct cross-site scripting (XSS)
attacks. With cross-site scripting vulnerabilities, if a user were
tricked into viewing a specially crafted page and had JavaScript
enabled, a remote attacker could exploit these to modify the contents,
or steal confidential data, within the same domain. (CVE-2012-3993,
CVE-2012-3994, CVE-2012-4184)

Abhishek Arya, Atte Kettunen and others discovered several memory
flaws in Thunderbird when using the Address Sanitizer tool. If a user
were tricked into opening a malicious website and had JavaScript
enabled, an attacker could exploit these to execute arbitrary
JavaScript code within the context of another website or execute
arbitrary code as the user invoking the program. (CVE-2012-3990,
CVE-2012-3995, CVE-2012-4179, CVE-2012-4180, CVE-2012-4181,
CVE-2012-4182, CVE-2012-4183, CVE-2012-4185, CVE-2012-4186,
CVE-2012-4187, CVE-2012-4188)

It was discovered that Thunderbird allowed improper access to the
Location object. An attacker could exploit this to obtain sensitive
information. Under certain circumstances, a remote attacker could use
this vulnerability to potentially execute arbitrary code as the user
invoking the program. (CVE-2012-4192, CVE-2012-4193).

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
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox 5.0 - 15.0.1 __exposedProps__ XCS Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/15");
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

if (ubuntu_check(osver:"10.04", pkgname:"thunderbird", pkgver:"16.0.1+build1-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"thunderbird", pkgver:"16.0.1+build1-0ubuntu0.11.04.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"thunderbird", pkgver:"16.0.1+build1-0ubuntu0.11.10.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"thunderbird", pkgver:"16.0.1+build1-0ubuntu0.12.04.1")) flag++;

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
