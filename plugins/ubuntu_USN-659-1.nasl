#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-659-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36681);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2007-6716", "CVE-2008-2372", "CVE-2008-3276", "CVE-2008-3525", "CVE-2008-3526", "CVE-2008-3534", "CVE-2008-3535", "CVE-2008-3792", "CVE-2008-3831", "CVE-2008-3915", "CVE-2008-4113", "CVE-2008-4445");
  script_bugtraq_id(31515, 31792);
  script_osvdb_id(48433);
  script_xref(name:"USN", value:"659-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.10 / 8.04 LTS : linux, linux-source-2.6.15/22 vulnerabilities (USN-659-1)");
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
"It was discovered that the direct-IO subsystem did not correctly
validate certain structures. A local attacker could exploit this to
cause a system crash, leading to a denial of service. (CVE-2007-6716)

It was discovered that the disabling of the ZERO_PAGE optimization
could lead to large memory consumption. A local attacker could exploit
this to allocate all available memory, leading to a denial of service.
(CVE-2008-2372)

It was discovered that the Datagram Congestion Control Protocol (DCCP)
did not correctly validate its arguments. If DCCP was in use, a remote
attacker could send specially crafted network traffic and cause a
system crash, leading to a denial of service. (CVE-2008-3276)

It was discovered that the SBNI WAN driver did not correctly check for
the NET_ADMIN capability. A malicious local root user lacking
CAP_NET_ADMIN would be able to change the WAN device configuration,
leading to a denial of service. (CVE-2008-3525)

It was discovered that the Stream Control Transmission Protocol (SCTP)
did not correctly validate the key length in the SCTP_AUTH_KEY option.
If SCTP is in use, a remote attacker could send specially crafted
network traffic that would crash the system, leading to a denial of
service. (CVE-2008-3526)

It was discovered that the tmpfs implementation did not correctly
handle certain sequences of inode operations. A local attacker could
exploit this to crash the system, leading to a denial of service.
(CVE-2008-3534)

It was discovered that the readv/writev functions did not correctly
handle certain sequences of file operations. A local attacker could
exploit this to crash the system, leading to a denial of service.
(CVE-2008-3535)

It was discovered that SCTP did not correctly validate its userspace
arguments. A local attacker could call certain sctp_* functions with
malicious options and cause a system crash, leading to a denial of
service. (CVE-2008-3792, CVE-2008-4113, CVE-2008-4445)

It was discovered the the i915 video driver did not correctly validate
memory addresses. A local attacker could exploit this to remap memory
that could cause a system crash, leading to a denial of service.
(CVE-2008-3831)

Johann Dahm and David Richter discovered that NFSv4 did not correctly
handle certain file ACLs. If NFSv4 is in use, a local attacker could
create a malicious ACL that could cause a system crash, leading to a
denial of service. (CVE-2008-3915).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 189, 200, 264, 399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"6.06", pkgname:"linux-doc-2.6.15", pkgver:"2.6.15-52.73")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52", pkgver:"2.6.15-52.73")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52-386", pkgver:"2.6.15-52.73")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52-686", pkgver:"2.6.15-52.73")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52-amd64-generic", pkgver:"2.6.15-52.73")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52-amd64-k8", pkgver:"2.6.15-52.73")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52-amd64-server", pkgver:"2.6.15-52.73")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52-amd64-xeon", pkgver:"2.6.15-52.73")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-52-server", pkgver:"2.6.15-52.73")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-52-386", pkgver:"2.6.15-52.73")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-52-686", pkgver:"2.6.15-52.73")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-52-amd64-generic", pkgver:"2.6.15-52.73")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-52-amd64-k8", pkgver:"2.6.15-52.73")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-52-amd64-server", pkgver:"2.6.15-52.73")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-52-amd64-xeon", pkgver:"2.6.15-52.73")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-52-server", pkgver:"2.6.15-52.73")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-kernel-devel", pkgver:"2.6.15-52.73")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-source-2.6.15", pkgver:"2.6.15-52.73")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-doc-2.6.22", pkgver:"2.6.22-15.59")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15", pkgver:"2.6.22-15.59")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15-386", pkgver:"2.6.22-15.59")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15-generic", pkgver:"2.6.22-15.59")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15-rt", pkgver:"2.6.22-15.59")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15-server", pkgver:"2.6.22-15.59")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15-ume", pkgver:"2.6.22-15.59")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15-virtual", pkgver:"2.6.22-15.59")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-headers-2.6.22-15-xen", pkgver:"2.6.22-15.59")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-386", pkgver:"2.6.22-15.59")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-cell", pkgver:"2.6.22-15.59")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-generic", pkgver:"2.6.22-15.59")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-lpia", pkgver:"2.6.22-15.59")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-lpiacompat", pkgver:"2.6.22-15.59")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-rt", pkgver:"2.6.22-15.59")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-server", pkgver:"2.6.22-15.59")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-ume", pkgver:"2.6.22-15.59")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-virtual", pkgver:"2.6.22-15.59")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-2.6.22-15-xen", pkgver:"2.6.22-15.59")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-15-386", pkgver:"2.6.22-15.59")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-15-generic", pkgver:"2.6.22-15.59")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-15-server", pkgver:"2.6.22-15.59")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-image-debug-2.6.22-15-virtual", pkgver:"2.6.22-15.59")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-kernel-devel", pkgver:"2.6.22-15.59")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-libc-dev", pkgver:"2.6.22-15.59")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"linux-source-2.6.22", pkgver:"2.6.22-15.59")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-doc-2.6.24", pkgver:"2.6.24-21.43")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-21", pkgver:"2.6.24-21.43")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-21-386", pkgver:"2.6.24-21.43")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-21-generic", pkgver:"2.6.24-21.43")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-21-openvz", pkgver:"2.6.24-21.43")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-21-rt", pkgver:"2.6.24-21.43")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-21-server", pkgver:"2.6.24-21.43")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-21-virtual", pkgver:"2.6.24-21.43")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-21-xen", pkgver:"2.6.24-21.43")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-21-386", pkgver:"2.6.24-21.43")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-21-generic", pkgver:"2.6.24-21.43")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-21-lpia", pkgver:"2.6.24-21.43")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-21-lpiacompat", pkgver:"2.6.24-21.43")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-21-openvz", pkgver:"2.6.24-21.43")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-21-rt", pkgver:"2.6.24-21.43")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-21-server", pkgver:"2.6.24-21.43")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-21-virtual", pkgver:"2.6.24-21.43")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-21-xen", pkgver:"2.6.24-21.43")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-21-386", pkgver:"2.6.24-21.43")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-21-generic", pkgver:"2.6.24-21.43")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-21-server", pkgver:"2.6.24-21.43")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-21-virtual", pkgver:"2.6.24-21.43")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-kernel-devel", pkgver:"2.6.24-21.43")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-libc-dev", pkgver:"2.6.24-21.43")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-source-2.6.24", pkgver:"2.6.24-21.43")) flag++;

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
