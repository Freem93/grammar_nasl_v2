#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2776-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86467);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/10/26 14:26:00 $");

  script_cve_id("CVE-2015-0272", "CVE-2015-5156", "CVE-2015-6937", "CVE-2015-7312");
  script_osvdb_id(125846, 127415, 127518, 127759);
  script_xref(name:"USN", value:"2776-1");

  script_name(english:"Ubuntu 14.04 LTS : linux vulnerabilities (USN-2776-1)");
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
"It was discovered that the Linux kernel did not check if a new IPv6
MTU set by a user space application was valid. A remote attacker could
forge a route advertisement with an invalid MTU that a user space
daemon like NetworkManager would honor and apply to the kernel,
causing a denial of service. (CVE-2015-0272)

It was discovered that virtio networking in the Linux kernel did not
handle fragments correctly, leading to kernel memory corruption. A
remote attacker could use this to cause a denial of service (system
crash) or possibly execute code with administrative privileges.
(CVE-2015-5156)

It was discovered that the Reliable Datagram Sockets (RDS)
implementation in the Linux kernel did not verify sockets were
properly bound before attempting to send a message, which could cause
a NULL pointer dereference. An attacker could use this to cause a
denial of service (system crash). (CVE-2015-6937)

Ben Hutchings discovered that the Advanced Union Filesystem (aufs) for
the Linux kernel did not correctly handle references of memory mapped
files from an aufs mount. A local attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code
with administrative privileges. (CVE-2015-7312).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected linux-image-3.13-generic,
linux-image-3.13-generic-lpae and / or linux-image-3.13-lowlatency
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-lowlatency");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2015-2016 Canonical, Inc. / NASL script (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.13.0-66-generic", pkgver:"3.13.0-66.108")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.13.0-66-generic-lpae", pkgver:"3.13.0-66.108")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.13.0-66-lowlatency", pkgver:"3.13.0-66.108")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.13-generic / linux-image-3.13-generic-lpae / etc");
}
