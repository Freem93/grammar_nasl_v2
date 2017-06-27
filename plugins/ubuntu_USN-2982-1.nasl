#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2982-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91220);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/01 21:07:49 $");

  script_cve_id("CVE-2016-4353", "CVE-2016-4354", "CVE-2016-4355", "CVE-2016-4356", "CVE-2016-4574", "CVE-2016-4579");
  script_osvdb_id(120763, 120764, 120765, 138450);
  script_xref(name:"USN", value:"2982-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.10 / 16.04 LTS : libksba vulnerabilities (USN-2982-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Hanno Bock discovered that Libksba incorrectly handled decoding
certain BER data. An attacker could use this issue to cause Libksba to
crash, resulting in a denial of service. This issue only applied to
Ubunt 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2016-4353)

Hanno Bock discovered that Libksba incorrectly handled decoding
certain BER data. An attacker could use this issue to cause Libksba to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only applied to Ubunt 12.04 LTS and Ubuntu 14.04 LTS.
(CVE-2016-4354, CVE-2016-4355)

Hanno Bock discovered that Libksba incorrectly handled incorrect
utf-8 strings when decoding certain DN data. An attacker could use
this issue to cause Libksba to crash, resulting in a denial of
service, or possibly execute arbitrary code. This issue only applied
to Ubunt 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2016-4356)

Pascal Cuoq discovered that Libksba incorrectly handled incorrect
utf-8 strings when decoding certain DN data. An attacker could use
this issue to cause Libksba to crash, resulting in a denial of
service, or possibly execute arbitrary code. (CVE-2016-4574)

Pascal Cuoq discovered that Libksba incorrectly handled decoding
certain data. An attacker could use this issue to cause Libksba to
crash, resulting in a denial of service. (CVE-2016-4579).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libksba8 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libksba8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/18");
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
if (! ereg(pattern:"^(12\.04|14\.04|15\.10|16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 15.10 / 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libksba8", pkgver:"1.2.0-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libksba8", pkgver:"1.3.0-3ubuntu0.14.04.2")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"libksba8", pkgver:"1.3.3-1ubuntu0.15.10.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libksba8", pkgver:"1.3.3-1ubuntu0.16.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libksba8");
}
