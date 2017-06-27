#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3260-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100153);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/05/22 13:36:33 $");

  script_cve_id("CVE-2017-5429", "CVE-2017-5430", "CVE-2017-5432", "CVE-2017-5433", "CVE-2017-5434", "CVE-2017-5435", "CVE-2017-5436", "CVE-2017-5437", "CVE-2017-5438", "CVE-2017-5439", "CVE-2017-5440", "CVE-2017-5441", "CVE-2017-5442", "CVE-2017-5443", "CVE-2017-5444", "CVE-2017-5445", "CVE-2017-5446", "CVE-2017-5447", "CVE-2017-5448", "CVE-2017-5449", "CVE-2017-5451", "CVE-2017-5453", "CVE-2017-5454", "CVE-2017-5455", "CVE-2017-5456", "CVE-2017-5458", "CVE-2017-5459", "CVE-2017-5460", "CVE-2017-5461", "CVE-2017-5462", "CVE-2017-5464", "CVE-2017-5465", "CVE-2017-5466", "CVE-2017-5467", "CVE-2017-5468", "CVE-2017-5469");
  script_osvdb_id(151245, 151246, 151247, 155950, 155951, 155952, 155953, 155954, 155955, 155956, 155957, 155958, 155959, 155960, 155961, 155962, 155963, 155964, 155965, 155966, 155967, 155968, 155972, 155973, 155974, 155975, 155976, 155989, 155991, 155992, 155994, 155996, 155997, 155998, 155999, 156037, 156038, 156039, 156040, 156041, 156042, 156043, 156044, 156045, 156046, 156047, 156048, 156049, 156050, 156051, 156052, 156053, 156054, 156055, 156056, 156057, 156058, 156059, 156139);
  script_xref(name:"USN", value:"3260-2");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 16.10 / 17.04 : firefox regression (USN-3260-2)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-3260-1 fixed vulnerabilities in Firefox. The update caused the
date picker panel and form validation errors to close immediately on
opening. This update fixes the problem.

We apologize for the inconvenience.

Multiple security issues were discovered in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, obtain
sensitive information, spoof the addressbar contents or other UI
elements, escape the sandbox to read local files, conduct cross-site
scripting (XSS) attacks, cause a denial of service via application
crash, or execute arbitrary code. (CVE-2017-5429, CVE-2017-5430,
CVE-2017-5432, CVE-2017-5433, CVE-2017-5434, CVE-2017-5435,
CVE-2017-5436, CVE-2017-5437, CVE-2017-5438, CVE-2017-5439,
CVE-2017-5440, CVE-2017-5441, CVE-2017-5442, CVE-2017-5443,
CVE-2017-5444, CVE-2017-5445, CVE-2017-5446, CVE-2017-5447,
CVE-2017-5448, CVE-2017-5449, CVE-2017-5451, CVE-2017-5453,
CVE-2017-5454, CVE-2017-5455, CVE-2017-5456, CVE-2017-5458,
CVE-2017-5459, CVE-2017-5460, CVE-2017-5461, CVE-2017-5464,
CVE-2017-5465, CVE-2017-5466, CVE-2017-5467, CVE-2017-5468,
CVE-2017-5469)

A flaw was discovered in the DRBG number generation in NSS.
If an attacker were able to perform a man-in-the-middle
attack, this flaw could potentially be exploited to view
sensitive information. (CVE-2017-5462).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2017 Canonical, Inc. / NASL script (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(14\.04|16\.04|16\.10|17\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 16.10 / 17.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"firefox", pkgver:"53.0.2+build1-0ubuntu0.14.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"firefox", pkgver:"53.0.2+build1-0ubuntu0.16.04.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"firefox", pkgver:"53.0.2+build1-0ubuntu0.16.10.2")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"firefox", pkgver:"53.0.2+build1-0ubuntu0.17.04.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox");
}
