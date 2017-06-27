#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2260-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76295);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/10/26 14:16:26 $");

  script_cve_id("CVE-2014-0077", "CVE-2014-0196", "CVE-2014-1737", "CVE-2014-1738", "CVE-2014-2568", "CVE-2014-2851", "CVE-2014-3122", "CVE-2014-3153");
  script_bugtraq_id(66348, 66678, 66779, 67162, 67199, 67300, 67302, 67906);
  script_osvdb_id(104745, 106527, 106646, 107752);
  script_xref(name:"USN", value:"2260-1");

  script_name(english:"Ubuntu 12.04 LTS : linux-lts-trusty vulnerabilities (USN-2260-1)");
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
"A flaw was discovered in the Linux kernel's pseudo tty (pty) device.
An unprivileged user could exploit this flaw to cause a denial of
service (system crash) or potentially gain administrator privileges.
(CVE-2014-0196)

Pinkie Pie discovered a flaw in the Linux kernel's futex subsystem. An
unprivileged local user could exploit this flaw to cause a denial of
service (system crash) or gain administrative privileges.
(CVE-2014-3153)

Matthew Daley reported an information leak in the floppy disk driver
of the Linux kernel. An unprivileged local user could exploit this
flaw to obtain potentially sensitive information from kernel memory.
(CVE-2014-1738)

Matthew Daley reported a flaw in the handling of ioctl commands by the
floppy disk driver in the Linux kernel. An unprivileged local user
could exploit this flaw to gain administrative privileges if the
floppy disk module is loaded. (CVE-2014-1737)

A flaw was discovered in the handling of network packets when
mergeable buffers are disabled for virtual machines in the Linux
kernel. Guest OS users may exploit this flaw to cause a denial of
service (host OS crash) or possibly gain privilege on the host OS.
(CVE-2014-0077)

An information leak was discovered in the netfilter subsystem of the
Linux kernel. An attacker could exploit this flaw to obtain sensitive
information from kernel memory. (CVE-2014-2568)

A flaw was discovered in the Linux kernel's ping sockets. An
unprivileged local user could exploit this flaw to cause a denial of
service (system crash) or possibly gain privileges via a crafted
application. (CVE-2014-2851)

Sasha Levin reported a bug in the Linux kernel's virtual memory
management subsystem. An unprivileged local user could exploit this
flaw to cause a denial of service (system crash). (CVE-2014-3122).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected linux-image-3.13-generic and / or
linux-image-3.13-generic-lpae packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Android \'Towelroot\' Futex Requeue Kernel Exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/28");
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
if (! ereg(pattern:"^(12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.13.0-30-generic", pkgver:"3.13.0-30.54~precise2")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.13.0-30-generic-lpae", pkgver:"3.13.0-30.54~precise2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.13-generic / linux-image-3.13-generic-lpae");
}
