#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1051-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51673);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/27 14:13:23 $");

  script_cve_id("CVE-2010-4267");
  script_bugtraq_id(45833);
  script_osvdb_id(70498);
  script_xref(name:"USN", value:"1051-1");

  script_name(english:"Ubuntu 8.04 LTS / 9.10 / 10.04 LTS / 10.10 : hplip vulnerability (USN-1051-1)");
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
"Sebastian Krahmer discovered that HPLIP incorrectly handled certain
long SNMP responses. A remote attacker could send malicious SNMP
replies to certain HPLIP tools and cause them to crash or possibly
execute arbitrary code.

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

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:hpijs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:hpijs-ppds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:hplip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:hplip-cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:hplip-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:hplip-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:hplip-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:hplip-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libhpmud-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libhpmud0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsane-hpaio");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2016 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(8\.04|9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"hpijs", pkgver:"2.8.2+2.8.2-0ubuntu8.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"hpijs-ppds", pkgver:"2.8.2+2.8.2-0ubuntu8.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"hplip", pkgver:"2.8.2-0ubuntu8.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"hplip-data", pkgver:"2.8.2-0ubuntu8.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"hplip-dbg", pkgver:"2.8.2-0ubuntu8.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"hplip-doc", pkgver:"2.8.2-0ubuntu8.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"hplip-gui", pkgver:"2.8.2-0ubuntu8.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"hpijs", pkgver:"3.9.8-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"hpijs-ppds", pkgver:"3.9.8-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"hplip", pkgver:"3.9.8-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"hplip-cups", pkgver:"3.9.8-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"hplip-data", pkgver:"3.9.8-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"hplip-dbg", pkgver:"3.9.8-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"hplip-doc", pkgver:"3.9.8-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"hplip-gui", pkgver:"3.9.8-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"hpijs", pkgver:"3.10.2-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"hpijs-ppds", pkgver:"3.10.2-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"hplip", pkgver:"3.10.2-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"hplip-cups", pkgver:"3.10.2-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"hplip-data", pkgver:"3.10.2-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"hplip-dbg", pkgver:"3.10.2-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"hplip-doc", pkgver:"3.10.2-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"hplip-gui", pkgver:"3.10.2-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libhpmud-dev", pkgver:"3.10.2-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libhpmud0", pkgver:"3.10.2-2ubuntu2.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"hpijs", pkgver:"3.10.6-1ubuntu10.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"hpijs-ppds", pkgver:"3.10.6-1ubuntu10.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"hplip", pkgver:"3.10.6-1ubuntu10.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"hplip-cups", pkgver:"3.10.6-1ubuntu10.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"hplip-data", pkgver:"3.10.6-1ubuntu10.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"hplip-dbg", pkgver:"3.10.6-1ubuntu10.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"hplip-doc", pkgver:"3.10.6-1ubuntu10.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"hplip-gui", pkgver:"3.10.6-1ubuntu10.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libhpmud-dev", pkgver:"3.10.6-1ubuntu10.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libhpmud0", pkgver:"3.10.6-1ubuntu10.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libsane-hpaio", pkgver:"3.10.6-1ubuntu10.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hpijs / hpijs-ppds / hplip / hplip-cups / hplip-data / hplip-dbg / etc");
}
