#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2877-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88455);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/01 20:56:52 $");

  script_cve_id("CVE-2016-1612", "CVE-2016-1614", "CVE-2016-1617", "CVE-2016-1618", "CVE-2016-1620", "CVE-2016-2051", "CVE-2016-2052");
  script_osvdb_id(129365, 132005, 133436, 133439, 133440, 133442, 133443, 133444, 133445, 133446, 133447, 133448, 133449, 133450, 133488, 133489, 133490, 133495, 133496, 133507, 133521, 133536, 133537, 133538, 133539, 133540, 133541, 133542, 133543, 133544, 133545, 141594);
  script_xref(name:"USN", value:"2877-1");

  script_name(english:"Ubuntu 14.04 LTS / 15.04 / 15.10 : oxide-qt vulnerabilities (USN-2877-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A bad cast was discovered in V8. If a user were tricked in to opening
a specially crafted website, an attacker could potentially exploit
this to cause a denial of service via renderer crash or execute
arbitrary code with the privileges of the sandboxed render process.
(CVE-2016-1612)

An issue was discovered when initializing the
UnacceleratedImageBufferSurface class in Blink. If a user were tricked
in to opening a specially crafted website, an attacker could
potentially exploit this to obtain sensitive information.
(CVE-2016-1614)

An issue was discovered with the CSP implementation in Blink. If a
user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to determine whether specific
HSTS sites had been visited by reading a CSP report. (CVE-2016-1617)

An issue was discovered with random number generator in Blink. An
attacker could potentially exploit this to defeat cryptographic
protection mechanisms. (CVE-2016-1618)

Multiple security issues were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via application crash or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2016-1620)

Multiple security issues were discovered in V8. If a user were tricked
in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via renderer crash or execute arbitrary code with the
privileges of the sandboxed render process. (CVE-2016-2051)

Multiple security issues were discovered in Harfbuzz. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via renderer
crash or execute arbitrary code with the privileges of the sandboxed
render process. (CVE-2016-2052).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected liboxideqtcore0 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liboxideqtcore0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016 Canonical, Inc. / NASL script (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(14\.04|15\.04|15\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 15.04 / 15.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"liboxideqtcore0", pkgver:"1.12.5-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"liboxideqtcore0", pkgver:"1.12.5-0ubuntu0.15.04.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"liboxideqtcore0", pkgver:"1.12.5-0ubuntu0.15.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "liboxideqtcore0");
}
