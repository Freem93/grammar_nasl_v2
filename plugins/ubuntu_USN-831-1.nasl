#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-831-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40982);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2009-1720", "CVE-2009-1721", "CVE-2009-1722");
  script_bugtraq_id(35838);
  script_osvdb_id(56707, 56708, 56709);
  script_xref(name:"USN", value:"831-1");

  script_name(english:"Ubuntu 8.04 LTS / 8.10 / 9.04 : openexr vulnerabilities (USN-831-1)");
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
"Drew Yao discovered several flaws in the way OpenEXR handled certain
malformed EXR image files. If a user were tricked into opening a
crafted EXR image file, an attacker could cause a denial of service
via application crash, or possibly execute arbitrary code with the
privileges of the user invoking the program. (CVE-2009-1720,
CVE-2009-1721)

It was discovered that OpenEXR did not properly handle certain
malformed EXR image files. If a user were tricked into opening a
crafted EXR image file, an attacker could cause a denial of service
via application crash, or possibly execute arbitrary code with the
privileges of the user invoking the program. This issue only affected
Ubuntu 8.04 LTS. (CVE-2009-1722).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopenexr-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopenexr2ldbl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopenexr6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openexr");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(8\.04|8\.10|9\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 8.10 / 9.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"libopenexr-dev", pkgver:"1.2.2-4.4ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libopenexr2ldbl", pkgver:"1.2.2-4.4ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openexr", pkgver:"1.2.2-4.4ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libopenexr-dev", pkgver:"1.6.1-3ubuntu1.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libopenexr6", pkgver:"1.6.1-3ubuntu1.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"openexr", pkgver:"1.6.1-3ubuntu1.8.10.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libopenexr-dev", pkgver:"1.6.1-3ubuntu1.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libopenexr6", pkgver:"1.6.1-3ubuntu1.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openexr", pkgver:"1.6.1-3ubuntu1.9.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libopenexr-dev / libopenexr2ldbl / libopenexr6 / openexr");
}
