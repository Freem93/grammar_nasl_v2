#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1063-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51986);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/27 14:13:23 $");

  script_cve_id("CVE-2011-0011");
  script_bugtraq_id(45743);
  script_xref(name:"USN", value:"1063-1");

  script_name(english:"Ubuntu 9.10 / 10.04 LTS / 10.10 : qemu-kvm vulnerability (USN-1063-1)");
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
"Neil Wilson discovered that if VNC passwords were blank in QEMU
configurations, access to VNC sessions was allowed without a password
instead of being disabled. A remote attacker could connect to running
VNC sessions of QEMU and directly control the system. By default, QEMU
does not start VNC sessions.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-arm-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-kvm-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-kvm-extras-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/15");
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
if (! ereg(pattern:"^(9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"9.10", pkgname:"kvm", pkgver:"0.11.0-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"qemu", pkgver:"0.11.0-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"qemu-arm-static", pkgver:"0.11.0-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"qemu-kvm", pkgver:"0.11.0-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"qemu-kvm-extras", pkgver:"0.11.0-0ubuntu6.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"kvm", pkgver:"0.12.3+noroms-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"qemu", pkgver:"0.12.3+noroms-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"qemu-arm-static", pkgver:"0.12.3+noroms-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"qemu-common", pkgver:"0.12.3+noroms-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"qemu-kvm", pkgver:"0.12.3+noroms-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"qemu-kvm-extras", pkgver:"0.12.3+noroms-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"qemu-kvm-extras-static", pkgver:"0.12.3+noroms-0ubuntu9.4")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"kvm", pkgver:"0.12.5+noroms-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"qemu", pkgver:"0.12.5+noroms-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"qemu-arm-static", pkgver:"0.12.5+noroms-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"qemu-common", pkgver:"0.12.5+noroms-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"qemu-kvm", pkgver:"0.12.5+noroms-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"qemu-kvm-extras", pkgver:"0.12.5+noroms-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"qemu-kvm-extras-static", pkgver:"0.12.5+noroms-0ubuntu7.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kvm / qemu / qemu-arm-static / qemu-common / qemu-kvm / etc");
}
