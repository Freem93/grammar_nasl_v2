#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1111-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55069);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/10/26 14:05:56 $");

  script_cve_id("CVE-2010-4164", "CVE-2010-4249", "CVE-2010-4258", "CVE-2010-4342", "CVE-2010-4527", "CVE-2010-4529", "CVE-2011-0521", "CVE-2011-0695", "CVE-2011-1017");
  script_bugtraq_id(45037, 45055, 45159, 45321, 45556, 45629, 45986, 46512, 46839);
  script_osvdb_id(69527, 70166, 70239, 70240, 70265, 70269, 70291, 70665, 71359, 71480);
  script_xref(name:"USN", value:"1111-1");

  script_name(english:"Ubuntu 6.06 LTS : linux-source-2.6.15 vulnerabilities (USN-1111-1)");
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
"Dan Rosenberg discovered multiple flaws in the X.25 facilities
parsing. If a system was using X.25, a remote attacker could exploit
this to crash the system, leading to a denial of service.
(CVE-2010-4164)

Vegard Nossum discovered that memory garbage collection was not
handled correctly for active sockets. A local attacker could exploit
this to allocate all available kernel memory, leading to a denial of
service. (CVE-2010-4249)

Nelson Elhage discovered that the kernel did not correctly handle
process cleanup after triggering a recoverable kernel bug. If a local
attacker were able to trigger certain kinds of kernel bugs, they could
create a specially crafted process to gain root privileges.
(CVE-2010-4258)

Nelson Elhage discovered that Econet did not correctly handle AUN
packets over UDP. A local attacker could send specially crafted
traffic to crash the system, leading to a denial of service.
(CVE-2010-4342)

Dan Rosenberg discovered that the OSS subsystem did not handle name
termination correctly. A local attacker could exploit this crash the
system or gain root privileges. (CVE-2010-4527)

Dan Rosenberg discovered that IRDA did not correctly check the size of
buffers. On non-x86 systems, a local attacker could exploit this to
read kernel heap memory, leading to a loss of privacy. (CVE-2010-4529)

Dan Carpenter discovered that the TTPCI DVB driver did not check
certain values during an ioctl. If the dvb-ttpci module was loaded, a
local attacker could exploit this to crash the system, leading to a
denial of service, or possibly gain root privileges. (CVE-2011-0521)

Jens Kuehnel discovered that the InfiniBand driver contained a race
condition. On systems using InfiniBand, a local attacker could send
specially crafted requests to crash the system, leading to a denial of
service. (CVE-2011-0695)

Timo Warns discovered that the LDM disk partition handling code did
not correctly handle certain values. By inserting a specially crafted
disk device, a local attacker could exploit this to gain root
privileges. (CVE-2011-1017).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/13");
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
if (! ereg(pattern:"^(6\.06)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-57-386", pkgver:"2.6.15-57.97")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-57-686", pkgver:"2.6.15-57.97")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-57-amd64-generic", pkgver:"2.6.15-57.97")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-57-amd64-k8", pkgver:"2.6.15-57.97")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-57-amd64-server", pkgver:"2.6.15-57.97")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-57-amd64-xeon", pkgver:"2.6.15-57.97")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-57-server", pkgver:"2.6.15-57.97")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-2.6-386 / linux-image-2.6-686 / etc");
}
