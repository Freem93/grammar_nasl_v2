#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-530-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28135);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/27 14:29:18 $");

  script_cve_id("CVE-2007-5208");
  script_bugtraq_id(26054);
  script_osvdb_id(41693);
  script_xref(name:"USN", value:"530-1");

  script_name(english:"Ubuntu 6.10 / 7.04 : hplip vulnerability (USN-530-1)");
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
"It was discovered that the hpssd tool of hplip did not correctly
handle shell meta-characters. A local attacker could exploit this to
execute arbitrary commands as the hplip user.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HPLIP hpssd.py From Address Arbitrary Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:hpijs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:hpijs-ppds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:hplip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:hplip-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:hplip-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:hplip-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2007-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.10|7\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.10 / 7.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.10", pkgname:"hpijs", pkgver:"2.6.9+1.6.9-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"hpijs-ppds", pkgver:"2.6.9+1.6.9-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"hplip", pkgver:"1.6.9-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"hplip-data", pkgver:"1.6.9-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"hplip-dbg", pkgver:"1.6.9-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"hplip-doc", pkgver:"1.6.9-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"hpijs", pkgver:"2.7.2+1.7.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"hpijs-ppds", pkgver:"2.7.2+1.7.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"hplip", pkgver:"1.7.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"hplip-data", pkgver:"1.7.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"hplip-dbg", pkgver:"1.7.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"hplip-doc", pkgver:"1.7.3-0ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hpijs / hpijs-ppds / hplip / hplip-data / hplip-dbg / hplip-doc");
}
