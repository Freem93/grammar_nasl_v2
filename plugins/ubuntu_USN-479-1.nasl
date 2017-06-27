#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-479-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28080);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/10/26 14:26:01 $");

  script_cve_id("CVE-2006-7177", "CVE-2006-7178", "CVE-2006-7179", "CVE-2006-7180", "CVE-2007-2829", "CVE-2007-2830", "CVE-2007-2831");
  script_osvdb_id(36635, 36636, 36637);
  script_xref(name:"USN", value:"479-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 : linux-restricted-modules-2.6.15/.17/.20 vulnerabilities (USN-479-1)");
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
"Multiple flaws in the MadWifi driver were discovered that could lead
to a system crash. A physically near-by attacker could generate
specially crafted wireless network traffic and cause a denial of
service. (CVE-2006-7177, CVE-2006-7178, CVE-2006-7179, CVE-2007-2829,
CVE-2007-2830)

A flaw was discovered in the MadWifi driver that would allow
unencrypted network traffic to be sent prior to finishing WPA
authentication. A physically near-by attacker could capture this,
leading to a loss of privacy, denial of service, or network spoofing.
(CVE-2006-7180)

A flaw was discovered in the MadWifi driver's ioctl handling. A local
attacker could read kernel memory, or crash the system, leading to a
denial of service. (CVE-2007-2831).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avm-fritz-firmware-2.6.15-28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avm-fritz-firmware-2.6.17-11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avm-fritz-firmware-2.6.20-16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avm-fritz-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fglrx-control");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fglrx-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-2.6-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-restricted-modules-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx-legacy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx-legacy-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx-new");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-glx-new-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-legacy-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-new-kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vmware-player-kernel-modules-2.6.17-11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vmware-player-kernel-modules-2.6.20-16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vmware-server-kernel-modules-2.6.20-16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vmware-tools-kernel-modules-2.6.20-16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-driver-fglrx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-driver-fglrx-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/23");
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
if (! ereg(pattern:"^(6\.06|6\.10|7\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 6.10 / 7.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"avm-fritz-firmware-2.6.15-28", pkgver:"3.11+2.6.15.12-28.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"avm-fritz-kernel-source", pkgver:"3.11+2.6.15.12-28.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"fglrx-control", pkgver:"8.25.18+2.6.15.12-28.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"fglrx-kernel-source", pkgver:"8.25.18+2.6.15.12-28.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-28-386", pkgver:"2.6.15.12-28.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-28-686", pkgver:"2.6.15.12-28.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-28-amd64-generic", pkgver:"2.6.15.12-28.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-28-amd64-k8", pkgver:"2.6.15.12-28.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-2.6.15-28-amd64-xeon", pkgver:"2.6.15.12-28.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-restricted-modules-common", pkgver:"2.6.15.12-28.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-glx", pkgver:"1.0.8776+2.6.15.12-28.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-glx-dev", pkgver:"1.0.8776+2.6.15.12-28.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-glx-legacy", pkgver:"1.0.7174+2.6.15.12-28.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-glx-legacy-dev", pkgver:"1.0.7174+2.6.15.12-28.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-kernel-source", pkgver:"1.0.8776+2.6.15.12-28.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"nvidia-legacy-kernel-source", pkgver:"1.0.7174+2.6.15.12-28.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xorg-driver-fglrx", pkgver:"7.0.0-8.25.18+2.6.15.12-28.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"xorg-driver-fglrx-dev", pkgver:"7.0.0-8.25.18+2.6.15.12-28.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"avm-fritz-firmware-2.6.17-11", pkgver:"3.11+2.6.17.8-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"avm-fritz-kernel-source", pkgver:"3.11+2.6.17.8-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"fglrx-control", pkgver:"8.28.8+2.6.17.8-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"fglrx-kernel-source", pkgver:"8.28.8+2.6.17.8-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-restricted-modules-2.6.17-11-386", pkgver:"2.6.17.8-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-restricted-modules-2.6.17-11-generic", pkgver:"2.6.17.8-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-restricted-modules-common", pkgver:"2.6.17.8-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"nvidia-glx", pkgver:"1.0.8776+2.6.17.8-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"nvidia-glx-dev", pkgver:"1.0.8776+2.6.17.8-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"nvidia-glx-legacy", pkgver:"1.0.7184+2.6.17.8-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"nvidia-glx-legacy-dev", pkgver:"1.0.7184+2.6.17.8-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"nvidia-kernel-source", pkgver:"1.0.8776+2.6.17.8-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"nvidia-legacy-kernel-source", pkgver:"1.0.7184+2.6.17.8-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"vmware-player-kernel-modules-2.6.17-11", pkgver:"2.6.17.8-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"xorg-driver-fglrx", pkgver:"7.1.0-8.28.8+2.6.17.8-11.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"xorg-driver-fglrx-dev", pkgver:"7.1.0-8.28.8+2.6.17.8-11.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"avm-fritz-firmware-2.6.20-16", pkgver:"3.11+2.6.20.5-16.29")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"avm-fritz-kernel-source", pkgver:"3.11+2.6.20.5-16.29")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"fglrx-control", pkgver:"8.34.8+2.6.20.5-16.29")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"fglrx-kernel-source", pkgver:"8.34.8+2.6.20.5-16.29")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-restricted-modules-2.6.20-16-386", pkgver:"2.6.20.5-16.29")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-restricted-modules-2.6.20-16-generic", pkgver:"2.6.20.5-16.29")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-restricted-modules-2.6.20-16-lowlatency", pkgver:"2.6.20.5-16.29")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-restricted-modules-common", pkgver:"2.6.20.5-16.29")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"nvidia-glx", pkgver:"1.0.9631+2.6.20.5-16.29")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"nvidia-glx-dev", pkgver:"1.0.9631+2.6.20.5-16.29")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"nvidia-glx-legacy", pkgver:"1.0.7184+2.6.20.5-16.29")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"nvidia-glx-legacy-dev", pkgver:"1.0.7184+2.6.20.5-16.29")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"nvidia-glx-new", pkgver:"1.0.9755+2.6.20.5-16.29")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"nvidia-glx-new-dev", pkgver:"1.0.9755+2.6.20.5-16.29")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"nvidia-kernel-source", pkgver:"1.0.9631+2.6.20.5-16.29")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"nvidia-legacy-kernel-source", pkgver:"1.0.7184+2.6.20.5-16.29")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"nvidia-new-kernel-source", pkgver:"1.0.9755+2.6.20.5-16.29")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"vmware-player-kernel-modules-2.6.20-16", pkgver:"2.6.20.5-16.29")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"vmware-server-kernel-modules-2.6.20-16", pkgver:"2.6.20.5-16.29")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"vmware-tools-kernel-modules-2.6.20-16", pkgver:"2.6.20.5-16.29")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"xorg-driver-fglrx", pkgver:"7.1.0-8.34.8+2.6.20.5-16.29")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"xorg-driver-fglrx-dev", pkgver:"7.1.0-8.34.8+2.6.20.5-16.29")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "avm-fritz-firmware-2.6.15-28 / avm-fritz-firmware-2.6.17-11 / etc");
}
