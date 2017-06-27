#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2677-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85240);
  script_version("$Revision: 2.10 $");
  script_cvs_date("$Date: 2016/12/01 20:56:52 $");

  script_cve_id("CVE-2015-1270", "CVE-2015-1272", "CVE-2015-1276", "CVE-2015-1277", "CVE-2015-1280", "CVE-2015-1281", "CVE-2015-1283", "CVE-2015-1284", "CVE-2015-1285", "CVE-2015-1287", "CVE-2015-1289", "CVE-2015-1329", "CVE-2015-5605");
  script_osvdb_id(120056, 120535, 122039, 125001, 125056, 125059, 125062, 125064, 125065, 125066, 125067, 125069, 125070, 125071, 125072, 125073, 125081, 125082, 125083, 125084, 125085, 125086, 125087, 125088, 125089, 125090, 125091, 125092, 125093, 125094, 125095, 125749, 126963, 126964);
  script_xref(name:"USN", value:"2677-1");

  script_name(english:"Ubuntu 14.04 LTS / 15.04 : oxide-qt vulnerabilities (USN-2677-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An uninitialized value issue was discovered in ICU. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service. (CVE-2015-1270)

A use-after-free was discovered in the GPU process implementation in
Chromium. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial
of service via application crash, or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2015-1272)

A use-after-free was discovered in the IndexedDB implementation in
Chromium. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial
of service via application crash, or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2015-1276)

A use-after-free was discovered in the accessibility implemetation in
Chromium. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial
of service via application crash, or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2015-1277)

A memory corruption issue was discovered in Skia. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via renderer
crash, or execute arbitrary code with the privileges of the sandboxed
render process. (CVE-2015-1280)

It was discovered that Blink did not properly determine the V8 context
of a microtask in some circumstances. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to bypass Content Security Policy (CSP) restrictions.
(CVE-2015-1281)

Multiple integer overflows were discovered in Expat. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user
invoking the program. (CVE-2015-1283)

It was discovered that Blink did not enforce a page's maximum number
of frames in some circumstances, resulting in a use-after-free. If a
user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of service
via renderer crash, or execute arbitrary code with the privileges of
the sandboxed render process. (CVE-2015-1284)

It was discovered that the XSS auditor in Blink did not properly
choose a truncation point. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this
to obtain sensitive information. (CVE-2015-1285)

An issue was discovered in the CSS implementation in Blink. If a user
were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to bypass same-origin restrictions.
(CVE-2015-1287)

Multiple security issues were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via application crash or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2015-1289)

A use-after-free was discovered in oxide::qt::URLRequestDelegatedJob
in some circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this
to cause a denial of service via application crash, or execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2015-1329)

A crash was discovered in the regular expression implementation in V8
in some circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this
to cause a denial of service. (CVE-2015-5605).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected liboxideqtcore0 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liboxideqtcore0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/05");
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
if (! ereg(pattern:"^(14\.04|15\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 15.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"liboxideqtcore0", pkgver:"1.8.4-0ubuntu0.14.04.2")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"liboxideqtcore0", pkgver:"1.8.4-0ubuntu0.15.04.1")) flag++;

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
