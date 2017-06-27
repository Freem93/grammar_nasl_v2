#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1192-3. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56562);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/26 16:14:09 $");

  script_cve_id("CVE-2011-0084", "CVE-2011-2985", "CVE-2011-2987", "CVE-2011-2988", "CVE-2011-2989", "CVE-2011-2990", "CVE-2011-2991", "CVE-2011-2993");
  script_bugtraq_id(49213, 49224, 49226, 49239, 49242, 49243, 49246, 49248);
  script_xref(name:"USN", value:"1192-3");

  script_name(english:"Ubuntu 11.04 : libvoikko regression (USN-1192-3)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-1192-1 provided Firefox 6 as a security upgrade. Unfortunately,
this caused a regression in libvoikko which caused Firefox to crash
while spell checking words with hyphens. This update corrects the
issue. We apologize for the inconvenience.

Aral Yaman discovered a vulnerability in the WebGL engine. An attacker
could potentially use this to crash Firefox or execute arbitrary code
with the privileges of the user invoking Firefox. (CVE-2011-2989)

Vivekanand Bolajwar discovered a vulnerability in the
JavaScript engine. An attacker could potentially use this to
crash Firefox or execute arbitrary code with the privileges
of the user invoking Firefox. (CVE-2011-2991)

Bert Hubert and Theo Snelleman discovered a vulnerability in
the Ogg reader. An attacker could potentially use this to
crash Firefox or execute arbitrary code with the privileges
of the user invoking Firefox. (CVE-2011-2991)

Robert Kaiser, Jesse Ruderman, Gary Kwong, Christoph Diehl,
Martijn Wargers, Travis Emmitt, Bob Clary, and Jonathan Watt
discovered multiple memory vulnerabilities in the browser
rendering engine. An attacker could use these to possibly
execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2011-2985)

Rafael Gieschke discovered that unsigned JavaScript could
call into a script inside a signed JAR. This could allow an
attacker to execute arbitrary code with the identity and
permissions of the signed JAR. (CVE-2011-2993)

Michael Jordon discovered that an overly long shader program
could cause a buffer overrun. An attacker could potentially
use this to crash Firefox or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2011-2988)

Michael Jordon discovered a heap overflow in the ANGLE
library used in Firefox's WebGL implementation. An attacker
could potentially use this to crash Firefox or execute
arbitrary code with the privileges of the user invoking
Firefox. (CVE-2011-2987)

It was discovered that an SVG text manipulation routine
contained a dangling pointer vulnerability. An attacker
could potentially use this to crash Firefox or execute
arbitrary code with the privileges of the user invoking
Firefox. (CVE-2011-0084)

Mike Cardwell discovered that Content Security Policy
violation reports failed to strip out proxy authorization
credentials from the list of request headers. This could
allow a malicious website to capture proxy authorization
credentials. Daniel Veditz discovered that redirecting to a
website with Content Security Policy resulted in the
incorrect resolution of hosts in the constructed policy.
This could allow a malicious website to circumvent the
Content Security Policy of another website. (CVE-2011-2990).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvoikko1 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvoikko1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/20");
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

if (ubuntu_check(osver:"11.04", pkgname:"libvoikko1", pkgver:"3.1-1ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvoikko1");
}
