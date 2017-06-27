#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-464-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28064);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/01 21:07:51 $");

  script_cve_id("CVE-2007-1357", "CVE-2007-1388", "CVE-2007-1496", "CVE-2007-1497", "CVE-2007-1592", "CVE-2007-1730", "CVE-2007-1734", "CVE-2007-2172");
  script_bugtraq_id(23104, 23162);
  script_osvdb_id(33026, 33027, 33028, 34365, 34737, 34738, 37120, 37121);
  script_xref(name:"USN", value:"464-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 : linux-source-2.6.15/2.6.17/2.6.20 vulnerabilities (USN-464-1)");
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
"Philipp Richter discovered that the AppleTalk protocol handler did not
sufficiently verify the length of packets. By sending a crafted
AppleTalk packet, a remote attacker could exploit this to crash the
kernel. (CVE-2007-1357)

Gabriel Campana discovered that the do_ipv6_setsockopt() function did
not sufficiently verifiy option values for IPV6_RTHDR. A local
attacker could exploit this to trigger a kernel crash. (CVE-2007-1388)

A Denial of Service vulnerability was discovered in the
nfnetlink_log() netfilter function. A remote attacker could exploit
this to trigger a kernel crash. (CVE-2007-1496)

The connection tracking module for IPv6 did not properly handle the
status field when reassembling fragmented packets, so that the final
packet always had the 'established' state. A remote attacker could
exploit this to bypass intended firewall rules. (CVE-2007-1497)

Masayuki Nakagawa discovered an error in the flowlabel handling of
IPv6 network sockets. A local attacker could exploit this to crash the
kernel. (CVE-2007-1592)

The do_dccp_getsockopt() function did not sufficiently verify the
optlen argument. A local attacker could exploit this to read kernel
memory (which might expose sensitive data) or cause a kernel crash.
This only affects Ubuntu 7.04. (CVE-2007-1730)

The IPv4 and DECnet network protocol handlers incorrectly declared an
array variable so that it became smaller than intended. By sending
crafted packets over a netlink socket, a local attacker could exploit
this to crash the kernel. (CVE-2007-2172).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.20");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/06");
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

if (ubuntu_check(osver:"6.06", pkgname:"linux-doc-2.6.15", pkgver:"2.6.15-28.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-28", pkgver:"2.6.15-28.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-28-386", pkgver:"2.6.15-28.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-28-686", pkgver:"2.6.15-28.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-28-amd64-generic", pkgver:"2.6.15-28.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-28-amd64-k8", pkgver:"2.6.15-28.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-28-amd64-server", pkgver:"2.6.15-28.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-28-amd64-xeon", pkgver:"2.6.15-28.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-28-server", pkgver:"2.6.15-28.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-28-386", pkgver:"2.6.15-28.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-28-686", pkgver:"2.6.15-28.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-28-amd64-generic", pkgver:"2.6.15-28.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-28-amd64-k8", pkgver:"2.6.15-28.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-28-amd64-server", pkgver:"2.6.15-28.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-28-amd64-xeon", pkgver:"2.6.15-28.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-28-server", pkgver:"2.6.15-28.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-kernel-devel", pkgver:"2.6.15-28.55")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-source-2.6.15", pkgver:"2.6.15-28.55")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-doc-2.6.17", pkgver:"2.6.17.1-11.38")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-11", pkgver:"2.6.17.1-11.38")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-11-386", pkgver:"2.6.17.1-11.38")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-11-generic", pkgver:"2.6.17.1-11.38")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-11-server", pkgver:"2.6.17.1-11.38")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-2.6.17-11-386", pkgver:"2.6.17.1-11.38")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-2.6.17-11-generic", pkgver:"2.6.17.1-11.38")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-2.6.17-11-server", pkgver:"2.6.17.1-11.38")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-debug-2.6.17-11-386", pkgver:"2.6.17.1-11.38")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-debug-2.6.17-11-generic", pkgver:"2.6.17.1-11.38")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-debug-2.6.17-11-server", pkgver:"2.6.17.1-11.38")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-kdump", pkgver:"2.6.17.1-11.38")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-kernel-devel", pkgver:"2.6.17.1-11.38")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-libc-dev", pkgver:"2.6.17.1-11.38")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-source-2.6.17", pkgver:"2.6.17.1-11.38")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-doc-2.6.20", pkgver:"2.6.20-16.28")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-16", pkgver:"2.6.20-16.28")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-16-386", pkgver:"2.6.20-16.28")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-16-generic", pkgver:"2.6.20-16.28")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-16-lowlatency", pkgver:"2.6.20-16.28")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-headers-2.6.20-16-server", pkgver:"2.6.20-16.28")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-16-386", pkgver:"2.6.20-16.28")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-16-generic", pkgver:"2.6.20-16.28")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-16-lowlatency", pkgver:"2.6.20-16.28")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-2.6.20-16-server", pkgver:"2.6.20-16.28")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-16-386", pkgver:"2.6.20-16.28")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-16-generic", pkgver:"2.6.20-16.28")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-16-lowlatency", pkgver:"2.6.20-16.28")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-image-debug-2.6.20-16-server", pkgver:"2.6.20-16.28")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-kernel-devel", pkgver:"2.6.20-16.28")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-libc-dev", pkgver:"2.6.20-16.28")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"linux-source-2.6.20", pkgver:"2.6.20-16.28")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc-2.6.15 / linux-doc-2.6.17 / linux-doc-2.6.20 / etc");
}
