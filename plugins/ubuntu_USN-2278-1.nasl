#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2278-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76525);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/26 16:22:50 $");

  script_cve_id("CVE-2013-7345", "CVE-2014-0207", "CVE-2014-3478", "CVE-2014-3479", "CVE-2014-3480", "CVE-2014-3487", "CVE-2014-3538");
  script_bugtraq_id(66406, 68120, 68238, 68239, 68241, 68243, 68348);
  script_osvdb_id(104208, 108463, 108464, 108465, 108466, 108467);
  script_xref(name:"USN", value:"2278-1");

  script_name(english:"Ubuntu 10.04 LTS / 12.04 LTS / 13.10 / 14.04 LTS : file vulnerabilities (USN-2278-1)");
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
"Mike Frysinger discovered that the file awk script detector used
multiple wildcard with unlimited repetitions. An attacker could use
this issue to cause file to consume resources, resulting in a denial
of service. (CVE-2013-7345)

Francisco Alonso discovered that file incorrectly handled certain CDF
documents. A attacker could use this issue to cause file to hang or
crash, resulting in a denial of service. (CVE-2014-0207,
CVE-2014-3478, CVE-2014-3479, CVE-2014-3480, CVE-2014-3487)

Jan Kaluza discovered that file did not properly restrict the amount
of data read during regex searches. An attacker could use this issue
to cause file to consume resources, resulting in a denial of service.
(CVE-2014-3538).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected file and / or libmagic1 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagic1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/16");
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
if (! ereg(pattern:"^(10\.04|12\.04|13\.10|14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 12.04 / 13.10 / 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"file", pkgver:"5.03-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libmagic1", pkgver:"5.03-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"file", pkgver:"5.09-2ubuntu0.4")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libmagic1", pkgver:"5.09-2ubuntu0.4")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"file", pkgver:"5.11-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"libmagic1", pkgver:"5.11-2ubuntu4.3")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"file", pkgver:"1:5.14-2ubuntu3.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libmagic1", pkgver:"1:5.14-2ubuntu3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "file / libmagic1");
}
