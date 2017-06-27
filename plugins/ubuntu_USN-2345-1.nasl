#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2345-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78465);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/09/15 13:52:58 $");

  script_cve_id("CVE-2014-3178", "CVE-2014-3179", "CVE-2014-3188", "CVE-2014-3190", "CVE-2014-3191", "CVE-2014-3192", "CVE-2014-3194", "CVE-2014-3195", "CVE-2014-3197", "CVE-2014-3199", "CVE-2014-3200", "CVE-2014-7967");
  script_bugtraq_id(69709, 69710, 70262, 70273);
  script_osvdb_id(90542, 104972, 104974, 105009, 112753, 112764, 112836, 112932);
  script_xref(name:"USN", value:"2345-1");

  script_name(english:"Ubuntu 14.04 LTS : oxide-qt vulnerabilities (USN-2345-1)");
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
"Multiple use-after-free issues were discovered in Blink. If a user
were tricked in to opening a specially crafted website, an attacker
could potentially exploit these to cause a denial of service via
renderer crash, or execute arbitrary code with the privileges of the
sandboxed render process. (CVE-2014-3178, CVE-2014-3190,
CVE-2014-3191, CVE-2014-3192)

Multiple security issues were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via application crash or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2014-3179,
CVE-2014-3200)

It was discovered that Chromium did not properly handle the
interaction of IPC and V8. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this
to execute arbitrary code with the privileges of the user invoking the
program. (CVE-2014-3188)

A use-after-free was discovered in the web workers implementation in
Chromium. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial
of service via applicatin crash or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2014-3194)

It was discovered that V8 did not correctly handle JavaScript heap
allocations in some circumstances. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to steal sensitive information. (CVE-2014-3195)

It was discovered that Blink did not properly provide substitute data
for pages blocked by the XSS auditor. If a user were tricked in to
opening a specially crafter website, an attacker could potentially
exploit this to steal sensitive information. (CVE-2014-3197)

It was discovered that the wrap function for Event's in the V8
bindings in Blink produced an erroneous result in some circumstances.
If a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of service
by stopping a worker process that was handling an Event object.
(CVE-2014-3199)

Multiple security issues were discovered in V8. If a user were tricked
in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via renderer crash or execute arbitrary code with the
privileges of the sandboxed render process. (CVE-2014-7967).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected liboxideqtcore0, oxideqt-codecs and / or
oxideqt-codecs-extra packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liboxideqtcore0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:oxideqt-codecs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:oxideqt-codecs-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2016 Canonical, Inc. / NASL script (C) 2014-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"liboxideqtcore0", pkgver:"1.2.5-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"oxideqt-codecs", pkgver:"1.2.5-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"oxideqt-codecs-extra", pkgver:"1.2.5-0ubuntu0.14.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "liboxideqtcore0 / oxideqt-codecs / oxideqt-codecs-extra");
}
