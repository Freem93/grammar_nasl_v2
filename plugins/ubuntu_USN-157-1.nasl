#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-157-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20560);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/27 14:21:16 $");

  script_cve_id("CVE-2005-0989", "CVE-2005-1159", "CVE-2005-1160", "CVE-2005-1532", "CVE-2005-2261", "CVE-2005-2265", "CVE-2005-2269", "CVE-2005-2270", "CVE-2005-2353");
  script_xref(name:"USN", value:"157-1");

  script_name(english:"Ubuntu 4.10 / 5.04 : mozilla-thunderbird vulnerabilities (USN-157-1)");
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
"Vladimir V. Perepelitsa discovered a bug in Thunderbird's handling of
anonymous functions during regular expression string replacement. A
malicious HTML email could exploit this to capture a random block of
client memory. (CAN-2005-0989)

Georgi Guninski discovered that the types of certain XPInstall related
JavaScript objects were not sufficiently validated when they were
called. This could be exploited by malicious HTML email content to
crash Thunderbird or even execute arbitrary code with the privileges
of the user. (CAN-2005-1159) 

Thunderbird did not properly verify the values of XML DOM nodes. By
tricking the user to perform a common action like clicking on a link
or opening the context menu, a malicious HTML email could exploit this
to execute arbitrary JavaScript code with the full privileges of the
user. (CAN-2005-1160)

A variant of the attack described in CAN-2005-1160 (see USN-124-1) was
discovered. Additional checks were added to make sure JavaScript eval
and script objects are run with the privileges of the context that
created them, not the potentially elevated privilege of the context
calling them. (CAN-2005-1532)

Scripts in XBL controls from web content continued to be run even when
JavaScript was disabled. This could be combined with most script-based
exploits to attack people running vulnerable versions who thought
disabling JavaScript would protect them. (CAN-2005-2261)

The function for version comparison in the addons installer did not
properly verify the type of its argument. By passing specially crafted
JavaScript objects to it, a malicious website could crash Thunderbird
and possibly even execute arbitrary code with the privilege of the
user account Thunderbird runs in. (CAN-2005-2265)

The XHTML DOM node handler did not take namespaces into account when
verifying node types based on their names. For example, an XHTML email
could contain an <IMG> tag with malicious contents, which would then
be processed as the standard trusted HTML <img> tag. By tricking an
user to view a malicious email, this could be exploited to execute
attacker-specified code with the full privileges of the user.
(CAN-2005-2269) 

It was discovered that some objects were not created appropriately.
This allowed malicious web content scripts to trace back the creation
chain until they found a privileged object and execute code with
higher privileges than allowed by the current site. (CAN-2005-2270) 

Javier Fernandez-Sanguino Pena discovered that the run-mozilla.sh
script created temporary files in an unsafe way when running with
'debugging' enabled. This could allow a symlink attack to create or
overwrite arbitrary files with the privileges of the user invoking the
program. (CAN-2005-2353)

The update for Ubuntu 4.10 (Warty Warthog) also fixes several less
critical vulnerabilities which are not present in the Ubuntu 5.04
version. (MFSA-2005-02 to MFSA-2005-30; please see the following web
site for details:
http://www.mozilla.org/projects/security/known-vulnerabilities.html).
We apologize for the huge delay of this update; we changed our update
strategy for Mozilla products to make sure that such long delays will
not happen again.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Suite/Firefox compareTo() Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-offline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-typeaheadfind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/01");
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

if (ubuntu_check(osver:"4.10", pkgname:"mozilla-thunderbird", pkgver:"1.0.6-0ubuntu04.10")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-thunderbird-dev", pkgver:"1.0.6-0ubuntu04.10")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-thunderbird-inspector", pkgver:"1.0.6-0ubuntu04.10")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-thunderbird-offline", pkgver:"1.0.6-0ubuntu04.10")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mozilla-thunderbird-typeaheadfind", pkgver:"1.0.6-0ubuntu04.10")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-enigmail", pkgver:"0.92-1ubuntu05.04.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-thunderbird", pkgver:"1.0.6-0ubuntu05.04")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-thunderbird-dev", pkgver:"1.0.6-0ubuntu05.04")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-thunderbird-enigmail", pkgver:"0.92-1ubuntu05.04.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-thunderbird-inspector", pkgver:"1.0.6-0ubuntu05.04")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-thunderbird-offline", pkgver:"1.0.6-0ubuntu05.04")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"mozilla-thunderbird-typeaheadfind", pkgver:"1.0.6-0ubuntu05.04")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mozilla-enigmail / mozilla-thunderbird / mozilla-thunderbird-dev / etc");
}
