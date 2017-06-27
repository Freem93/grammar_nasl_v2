#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2522-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81698);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/24 17:37:08 $");

  script_cve_id("CVE-2013-1569", "CVE-2013-2383", "CVE-2013-2384", "CVE-2013-2419", "CVE-2014-6585", "CVE-2014-6591", "CVE-2014-7923", "CVE-2014-7926", "CVE-2014-7940", "CVE-2014-9654");
  script_bugtraq_id(59131, 59166, 59179, 59190, 72173, 72175, 72288, 72980);
  script_osvdb_id(92335, 92336, 92337, 92342, 117232, 117233, 117380, 117383, 117397, 117639);
  script_xref(name:"USN", value:"2522-2");

  script_name(english:"Ubuntu 12.04 LTS : icu regression (USN-2522-2)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-2522-1 fixed vulnerabilities in ICU. On Ubuntu 12.04 LTS, the font
patches caused a regression when using LibreOffice Calc. The patches
have been temporarily backed out until the regression is investigated.

We apologize for the inconvenience.

It was discovered that ICU incorrectly handled memory operations when
processing fonts. If an application using ICU processed crafted data,
an attacker could cause it to crash or potentially execute arbitrary
code with the privileges of the user invoking the program. This issue
only affected Ubuntu 12.04 LTS. (CVE-2013-1569, CVE-2013-2383,
CVE-2013-2384, CVE-2013-2419)

It was discovered that ICU incorrectly handled memory
operations when processing fonts. If an application using
ICU processed crafted data, an attacker could cause it to
crash or potentially execute arbitrary code with the
privileges of the user invoking the program. (CVE-2014-6585,
CVE-2014-6591)

It was discovered that ICU incorrectly handled memory
operations when processing regular expressions. If an
application using ICU processed crafted data, an attacker
could cause it to crash or potentially execute arbitrary
code with the privileges of the user invoking the program.
(CVE-2014-7923, CVE-2014-7926, CVE-2014-9654)

It was discovered that ICU collator implementation
incorrectly handled memory operations. If an application
using ICU processed crafted data, an attacker could cause it
to crash or potentially execute arbitrary code with the
privileges of the user invoking the program. (CVE-2014-7940).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libicu48 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libicu48");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2015-2016 Canonical, Inc. / NASL script (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libicu48", pkgver:"4.8.1.1-3ubuntu0.4")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libicu48");
}
