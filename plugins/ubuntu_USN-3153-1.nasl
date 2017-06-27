#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3153-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95661);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2017/02/06 16:27:35 $");

  script_cve_id("CVE-2016-5204", "CVE-2016-5205", "CVE-2016-5207", "CVE-2016-5208", "CVE-2016-5209", "CVE-2016-5212", "CVE-2016-5213", "CVE-2016-5215", "CVE-2016-5219", "CVE-2016-5221", "CVE-2016-5222", "CVE-2016-5224", "CVE-2016-5225", "CVE-2016-5226", "CVE-2016-9650", "CVE-2016-9651", "CVE-2016-9652");
  script_osvdb_id(148065, 148066, 148072, 148073, 148074, 148076, 148077, 148079, 148082, 148083, 148084, 148086, 148087, 148088, 148104, 148106, 148110, 148111, 148133, 148134, 148135, 148138, 148139, 148140, 148142);
  script_xref(name:"USN", value:"3153-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 16.10 : oxide-qt vulnerabilities (USN-3153-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to conduct cross-site scripting (XSS)
attacks, read uninitialized memory, obtain sensitive information,
spoof the webview URL, bypass same origin restrictions, cause a denial
of service via application crash, or execute arbitrary code.
(CVE-2016-5204, CVE-2016-5205, CVE-2016-5207, CVE-2016-5208,
CVE-2016-5209, CVE-2016-5212, CVE-2016-5215, CVE-2016-5222,
CVE-2016-5224, CVE-2016-5225, CVE-2016-5226, CVE-2016-9650,
CVE-2016-9652)

Multiple vulnerabilities were discovered in V8. If a user were tricked
in to opening a specially crafted website, an attacker could
potentially exploit these to obtain sensitive information, cause a
denial of service via application crash, or execute arbitrary code.
(CVE-2016-5213, CVE-2016-5219, CVE-2016-9651)

An integer overflow was discovered in ANGLE. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via application crash, or
execute arbitrary code. (CVE-2016-5221).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected liboxideqtcore0 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liboxideqtcore0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016-2017 Canonical, Inc. / NASL script (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(14\.04|16\.04|16\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 16.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"liboxideqtcore0", pkgver:"1.19.4-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"liboxideqtcore0", pkgver:"1.19.4-0ubuntu0.16.04.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"liboxideqtcore0", pkgver:"1.19.4-0ubuntu0.16.10.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
