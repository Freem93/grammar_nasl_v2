#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1941-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69809);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/10/26 14:16:25 $");

  script_cve_id("CVE-2013-1059", "CVE-2013-1060", "CVE-2013-2164", "CVE-2013-2232", "CVE-2013-2234", "CVE-2013-2851", "CVE-2013-4162", "CVE-2013-4163");
  script_bugtraq_id(60375, 60409, 60922);
  script_osvdb_id(94033, 94035, 94698, 94793, 94796, 95614, 95615, 97215);
  script_xref(name:"USN", value:"1941-1");

  script_name(english:"Ubuntu 12.04 LTS : linux vulnerabilities (USN-1941-1)");
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
"Chanam Park reported a NULL pointer flaw in the Linux kernel's Ceph
client. A remote attacker could exploit this flaw to cause a denial of
service (system crash). (CVE-2013-1059)

Vasily Kulikov discovered a flaw in the Linux Kernel's perf tool that
allows for privilege escalation. A local user could exploit this flaw
to run commands as root when using the perf tool. (CVE-2013-1060)

Jonathan Salwan discovered an information leak in the Linux kernel's
cdrom driver. A local user can exploit this leak to obtain sensitive
information from kernel memory if the CD-ROM drive is malfunctioning.
(CVE-2013-2164)

A flaw was discovered in the Linux kernel when an IPv6 socket is used
to connect to an IPv4 destination. An unprivileged local user could
exploit this flaw to cause a denial of service (system crash).
(CVE-2013-2232)

An information leak was discovered in the IPSec key_socket
implementation in the Linux kernel. An local user could exploit this
flaw to examine potentially sensitive information in kernel memory.
(CVE-2013-2234)

Kees Cook discovered a format string vulnerability in the Linux
kernel's disk block layer. A local user with administrator privileges
could exploit this flaw to gain kernel privileges. (CVE-2013-2851)

Hannes Frederic Sowa discovered a flaw in setsockopt UDP_CORK option
in the Linux kernel's IPv6 stack. A local user could exploit this flaw
to cause a denial of service (system crash). (CVE-2013-4162)

Hannes Frederic Sowa discovered a flaw in the IPv6 subsystem of the
Linux kernel when the IPV6_MTU setsockopt option has been specified in
combination with the UDP_CORK option. A local user could exploit this
flaw to cause a denial of service (system crash). (CVE-2013-4163).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-highbank");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2013-2016 Canonical, Inc. / NASL script (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-53-generic", pkgver:"3.2.0-53.81")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-53-generic-pae", pkgver:"3.2.0-53.81")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-53-highbank", pkgver:"3.2.0-53.81")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-53-virtual", pkgver:"3.2.0-53.81")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.2-generic / linux-image-3.2-generic-pae / etc");
}
