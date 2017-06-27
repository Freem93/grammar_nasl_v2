#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-714-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36454);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2008-5079", "CVE-2008-5134", "CVE-2008-5182", "CVE-2008-5300", "CVE-2008-5700", "CVE-2008-5702", "CVE-2008-5713");
  script_bugtraq_id(32676);
  script_xref(name:"USN", value:"714-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.10 / 8.04 LTS : linux-source-2.6.15/22, linux vulnerabilities (USN-714-1)");
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
"Hugo Dias discovered that the ATM subsystem did not correctly manage
socket counts. A local attacker could exploit this to cause a system
hang, leading to a denial of service. (CVE-2008-5079)

It was discovered that the libertas wireless driver did not correctly
handle beacon and probe responses. A physically near-by attacker could
generate specially crafted wireless network traffic and cause a denial
of service. Ubuntu 6.06 was not affected. (CVE-2008-5134)

It was discovered that the inotify subsystem contained watch removal
race conditions. A local attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2008-5182)

Dann Frazier discovered that in certain situations sendmsg did not
correctly release allocated memory. A local attacker could exploit
this to force the system to run out of free memory, leading to a
denial of service. Ubuntu 6.06 was not affected. (CVE-2008-5300)

It was discovered that the ATA subsystem did not correctly set
timeouts. A local attacker could exploit this to cause a system hang,
leading to a denial of service. (CVE-2008-5700)

It was discovered that the ib700 watchdog timer did not correctly
check buffer sizes. A local attacker could send a specially crafted
ioctl to the device to cause a system crash, leading to a denial of
service. (CVE-2008-5702)

It was discovered that in certain situations the network scheduler did
not correctly handle very large levels of traffic. A local attacker
could produce a high volume of UDP traffic resulting in a system hang,
leading to a denial of service. Ubuntu 8.04 was not affected.
(CVE-2008-5713).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-ume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-cell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpiacompat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-ume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.24");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
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
if (! ereg(pattern:"^(6\.06|7\.10|8\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.10 / 8.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"linux-doc-2.6.15", pkgver:"2.6.15-53.75")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-53", pkgver:"2.6.15-53.75")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-53-386", pkgver:"2.6.15-53.75")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-53-686", pkgver:"2.6.15-53.75")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-53-amd64-generic", pkgver:"2.6.15-53.75")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-53-amd64-k8", pkgver:"2.6.15-53.75")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-53-amd64-server", pkgver:"2.6.15-53.75")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-53-amd64-xeon", pkgver:"2.6.15-53.75")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-53-server", pkgver:"2.6.15-53.75")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-53-386", pkgver:"2.6.15-53.75")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-53-686", pkgver:"2.6.15-53.75")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-53-amd64-generic", pkgver:"2.6.15-53.75")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-53-amd64-k8", pkgver:"2.6.15-53.75")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-53-amd64-server", pkgver:"2.6.15-53.75")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-53-amd64-xeon", pkgver:"2.6.15-53.75")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-53-server", pkgver:"2.6.15-53.75")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-kernel-devel", pkgver:"2.6.15-53.75")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-source-2.6.15", pkgver:"2.6.15-53.75")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-doc-2.6.22", pkgver:"2.6.22-16.61")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-16", pkgver:"2.6.22-16.61")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-16-386", pkgver:"2.6.22-16.61")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-16-generic", pkgver:"2.6.22-16.61")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-16-rt", pkgver:"2.6.22-16.61")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-16-server", pkgver:"2.6.22-16.61")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-16-ume", pkgver:"2.6.22-16.61")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-16-virtual", pkgver:"2.6.22-16.61")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-16-xen", pkgver:"2.6.22-16.61")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-386", pkgver:"2.6.22-16.61")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-cell", pkgver:"2.6.22-16.61")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-generic", pkgver:"2.6.22-16.61")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-lpia", pkgver:"2.6.22-16.61")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-lpiacompat", pkgver:"2.6.22-16.61")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-rt", pkgver:"2.6.22-16.61")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-server", pkgver:"2.6.22-16.61")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-ume", pkgver:"2.6.22-16.61")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-virtual", pkgver:"2.6.22-16.61")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-16-xen", pkgver:"2.6.22-16.61")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-16-386", pkgver:"2.6.22-16.61")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-16-generic", pkgver:"2.6.22-16.61")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-16-server", pkgver:"2.6.22-16.61")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-16-virtual", pkgver:"2.6.22-16.61")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-kernel-devel", pkgver:"2.6.22-16.61")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-libc-dev", pkgver:"2.6.22-16.61")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-source-2.6.22", pkgver:"2.6.22-16.61")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-doc-2.6.24", pkgver:"2.6.24-23.48")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-23", pkgver:"2.6.24-23.48")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-23-386", pkgver:"2.6.24-23.48")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-23-generic", pkgver:"2.6.24-23.48")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-23-openvz", pkgver:"2.6.24-23.48")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-23-rt", pkgver:"2.6.24-23.48")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-23-server", pkgver:"2.6.24-23.48")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-23-virtual", pkgver:"2.6.24-23.48")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-23-xen", pkgver:"2.6.24-23.48")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-23-386", pkgver:"2.6.24-23.48")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-23-generic", pkgver:"2.6.24-23.48")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-23-lpia", pkgver:"2.6.24-23.48")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-23-lpiacompat", pkgver:"2.6.24-23.48")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-23-openvz", pkgver:"2.6.24-23.48")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-23-rt", pkgver:"2.6.24-23.48")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-23-server", pkgver:"2.6.24-23.48")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-23-virtual", pkgver:"2.6.24-23.48")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-23-xen", pkgver:"2.6.24-23.48")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-23-386", pkgver:"2.6.24-23.48")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-23-generic", pkgver:"2.6.24-23.48")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-23-server", pkgver:"2.6.24-23.48")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-23-virtual", pkgver:"2.6.24-23.48")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-kernel-devel", pkgver:"2.6.24-23.48")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-libc-dev", pkgver:"2.6.24-23.48")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-source-2.6.24", pkgver:"2.6.24-23.48")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc-2.6.15 / linux-doc-2.6.22 / linux-doc-2.6.24 / etc");
}
