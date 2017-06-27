#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2219-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74182);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/10/26 14:16:26 $");

  script_cve_id("CVE-2013-7339", "CVE-2014-1737", "CVE-2014-1738", "CVE-2014-2678");
  script_bugtraq_id(66351, 66543, 67300, 67302);
  script_xref(name:"USN", value:"2219-1");

  script_name(english:"Ubuntu 10.04 LTS : linux vulnerabilities (USN-2219-1)");
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

A flaw was discovered in the Reliable Datagram Sockets (RDS) protocol
implementation in the Linux kernel for systems that lack RDS
transports. An unprivileged local user could exploit this flaw to
cause a denial of service (system crash). (CVE-2013-7339)

An error was discovered in the Reliable Datagram Sockets (RDS)
protocol stack in the Linux kernel. A local user could exploit this
flaw to cause a denial of service (system crash) or possibly have
unspecified other impact. (CVE-2014-2678).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-versatile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/27");
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
if (! ereg(pattern:"^(10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-60-386", pkgver:"2.6.32-60.122")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-60-generic", pkgver:"2.6.32-60.122")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-60-generic-pae", pkgver:"2.6.32-60.122")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-60-lpia", pkgver:"2.6.32-60.122")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-60-preempt", pkgver:"2.6.32-60.122")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-60-server", pkgver:"2.6.32-60.122")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-60-versatile", pkgver:"2.6.32-60.122")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-60-virtual", pkgver:"2.6.32-60.122")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-2.6-386 / linux-image-2.6-generic / etc");
}
