#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1185-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55982);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/26 16:14:08 $");

  script_cve_id("CVE-2011-0084", "CVE-2011-2378", "CVE-2011-2981", "CVE-2011-2982", "CVE-2011-2983", "CVE-2011-2984");
  script_bugtraq_id(49213, 49214, 49216, 49218, 49219, 49223);
  script_osvdb_id(74581, 74582, 74584, 74585, 74586, 74587);
  script_xref(name:"USN", value:"1185-1");

  script_name(english:"Ubuntu 10.04 LTS / 10.10 / 11.04 : thunderbird vulnerabilities (USN-1185-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Gary Kwong, Igor Bukanov, and Bob Clary discovered multiple memory
vulnerabilities in the Gecko rendering engine. An attacker could use
these to possibly execute arbitrary code with the privileges of the
user invoking Thunderbird. (CVE-2011-2982)

It was discovered that a vulnerability in event management code could
permit JavaScript to be run in the wrong context. This could
potentially allow a malicious website to run code as another website
or with escalated privileges in a chrome-privileged context.
(CVE-2011-2981)

It was discovered that an SVG text manipulation routine contained a
dangling pointer vulnerability. An attacker could potentially use this
to crash Thunderbird or execute arbitrary code with the privileges of
the user invoking Thunderbird. (CVE-2011-0084)

It was discovered that web content could receive chrome privileges if
it registered for drop events and a browser tab element was dropped
into the content area. This could potentially allow a malicious
website to run code with escalated privileges within Thunderbird.
(CVE-2011-2984)

It was discovered that appendChild contained a dangling pointer
vulnerability. An attacker could potentially use this to crash
Thunderbird or execute arbitrary code with the privileges of the user
invoking Thunderbird. (CVE-2011-2378)

It was discovered that data from other domains could be read when
RegExp.input was set. This could potentially allow a malicious website
access to private data from other domains. (CVE-2011-2983).

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

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/26");
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
if (! ereg(pattern:"^(10\.04|10\.10|11\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 10.10 / 11.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"thunderbird", pkgver:"3.1.12+build1+nobinonly-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"thunderbird", pkgver:"3.1.12+build1+nobinonly-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"thunderbird", pkgver:"3.1.12+build1+nobinonly-0ubuntu0.11.04.1")) flag++;

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
