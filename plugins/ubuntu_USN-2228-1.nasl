#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2228-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74215);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/10/26 14:16:26 $");

  script_cve_id("CVE-2014-0055", "CVE-2014-0077", "CVE-2014-0100", "CVE-2014-0101", "CVE-2014-1737", "CVE-2014-1738", "CVE-2014-2309", "CVE-2014-2523", "CVE-2014-2672", "CVE-2014-2673", "CVE-2014-2678", "CVE-2014-2706", "CVE-2014-2851");
  script_bugtraq_id(65943, 66095, 66279, 66441, 66477, 66492, 66543, 66591, 66678, 66779, 67300, 67302);
  script_osvdb_id(105302);
  script_xref(name:"USN", value:"2228-1");

  script_name(english:"Ubuntu 13.10 : linux vulnerabilities (USN-2228-1)");
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
"Matthew Daley reported an information leak in the floppy disk driver
of the Linux kernel. An unprivileged local user could exploit this
flaw to obtain potentially sensitive information from kernel memory.
(CVE-2014-1738)

Matthew Daley reported a flaw in the handling of ioctl commands by the
floppy disk driver in the Linux kernel. An unprivileged local user
could exploit this flaw to gain administrative privileges if the
floppy disk module is loaded. (CVE-2014-1737)

A flaw was discovered in the vhost-net subsystem of the Linux kernel.
Guest OS users could exploit this flaw to cause a denial of service
(host OS crash). (CVE-2014-0055)

A flaw was discovered in the handling of network packets when
mergeable buffers are disabled for virtual machines in the Linux
kernel. Guest OS users may exploit this flaw to cause a denial of
service (host OS crash) or possibly gain privilege on the host OS.
(CVE-2014-0077)

Nikolay Aleksandrov discovered a race condition in Linux kernel's IPv4
fragment handling code. Remote attackers could exploit this flaw to
cause a denial of service (system crash) or possibly have other
unspecified impact. (CVE-2014-0100)

A flaw was discovered in the Linux kernel's handling of the SCTP
handshake. A remote attacker could exploit this flaw to cause a denial
of service (system crash). (CVE-2014-0101)

A flaw was discovered in the handling of routing information in Linux
kernel's IPv6 stack. A remote attacker could exploit this flaw to
cause a denial of service (memory consumption) via a flood of ICMPv6
router advertisement packets. (CVE-2014-2309)

An error was discovered in the Linux kernel's DCCP protocol support. A
remote attacked could exploit this flaw to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2014-2523)

Max Sydorenko discovered a race condition in the Atheros 9k wireless
driver in the Linux kernel. This race could be exploited by remote
attackers to cause a denial of service (system crash). (CVE-2014-2672)

Adhemerval Zanella Neto discovered a flaw the in the Transactional
Memory (TM) implementation for powerpc based machine. An unprivileged
local user could exploit this flaw to cause a denial of service
(system crash). (CVE-2014-2673)

An error was discovered in the Reliable Datagram Sockets (RDS)
protocol stack in the Linux kernel. A local user could exploit this
flaw to cause a denial of service (system crash) or possibly have
unspecified other impact. (CVE-2014-2678)

Yaara Rozenblum discovered a race condition in the Linux kernel's
Generic IEEE 802.11 Networking Stack (mac80211). Remote attackers
could exploit this flaw to cause a denial of service (system crash).
(CVE-2014-2706)

A flaw was discovered in the Linux kernel's ping sockets. An
unprivileged local user could exploit this flaw to cause a denial of
service (system crash) or possibly gain privileges via a crafted
application. (CVE-2014-2851).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected linux-image-3.11-generic and / or
linux-image-3.11-generic-lpae packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.11-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.11-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/28");
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
if (! ereg(pattern:"^(13\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 13.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"13.10", pkgname:"linux-image-3.11.0-22-generic", pkgver:"3.11.0-22.38")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"linux-image-3.11.0-22-generic-lpae", pkgver:"3.11.0-22.38")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.11-generic / linux-image-3.11-generic-lpae");
}
