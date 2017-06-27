#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1186-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55784);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/10/26 14:05:57 $");

  script_cve_id("CVE-2010-4073", "CVE-2010-4165", "CVE-2010-4238", "CVE-2010-4249", "CVE-2010-4649", "CVE-2011-0711", "CVE-2011-1010", "CVE-2011-1044", "CVE-2011-1090", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-1173", "CVE-2011-2484", "CVE-2011-2534");
  script_bugtraq_id(44830, 45037, 45073, 45795, 46073, 46417, 46488, 46492, 46766, 46919, 46921, 47990, 48383);
  script_xref(name:"USN", value:"1186-1");

  script_name(english:"Ubuntu 8.04 LTS : linux vulnerabilities (USN-1186-1)");
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
"Dan Rosenberg discovered that IPC structures were not correctly
initialized on 64bit systems. A local attacker could exploit this to
read kernel stack memory, leading to a loss of privacy.
(CVE-2010-4073)

Steve Chen discovered that setsockopt did not correctly check MSS
values. A local attacker could make a specially crafted socket call to
crash the system, leading to a denial of service. (CVE-2010-4165)

Vladymyr Denysov discovered that Xen virtual CD-ROM devices were not
handled correctly. A local attacker in a guest could make crafted
blkback requests that would crash the host, leading to a denial of
service. (CVE-2010-4238)

Vegard Nossum discovered that memory garbage collection was not
handled correctly for active sockets. A local attacker could exploit
this to allocate all available kernel memory, leading to a denial of
service. (CVE-2010-4249)

Dan Carpenter discovered that the Infiniband driver did not correctly
handle certain requests. A local user could exploit this to crash the
system or potentially gain root privileges. (CVE-2010-4649,
CVE-2011-1044)

Dan Rosenberg discovered that XFS did not correctly initialize memory.
A local attacker could make crafted ioctl calls to leak portions of
kernel stack memory, leading to a loss of privacy. (CVE-2011-0711)

Timo Warns discovered that MAC partition parsing routines did not
correctly calculate block counts. A local attacker with physical
access could plug in a specially crafted block device to crash the
system or potentially gain root privileges. (CVE-2011-1010)

Neil Horman discovered that NFSv4 did not correctly handle certain
orders of operation with ACL data. A remote attacker with access to an
NFSv4 mount could exploit this to crash the system, leading to a
denial of service. (CVE-2011-1090)

Vasiliy Kulikov discovered that the netfilter code did not check
certain strings copied from userspace. A local attacker with netfilter
access could exploit this to read kernel memory or crash the system,
leading to a denial of service. (CVE-2011-1170, CVE-2011-1171,
CVE-2011-1172, CVE-2011-2534)

Vasiliy Kulikov discovered that the Acorn Universal Networking driver
did not correctly initialize memory. A remote attacker could send
specially crafted traffic to read kernel stack memory, leading to a
loss of privacy. (CVE-2011-1173)

Vasiliy Kulikov discovered that taskstats listeners were not correctly
handled. A local attacker could exploit this to exhaust memory and CPU
resources, leading to a denial of service. (CVE-2011-2484).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpiacompat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/09");
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
if (! ereg(pattern:"^(8\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-29-386", pkgver:"2.6.24-29.92")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-29-generic", pkgver:"2.6.24-29.92")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-29-lpia", pkgver:"2.6.24-29.92")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-29-lpiacompat", pkgver:"2.6.24-29.92")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-29-openvz", pkgver:"2.6.24-29.92")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-29-rt", pkgver:"2.6.24-29.92")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-29-server", pkgver:"2.6.24-29.92")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-29-virtual", pkgver:"2.6.24-29.92")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-29-xen", pkgver:"2.6.24-29.92")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-2.6-386 / linux-image-2.6-generic / etc");
}
