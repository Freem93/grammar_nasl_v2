#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1384-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58265);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/10/26 14:05:57 $");

  script_cve_id("CVE-2011-4097", "CVE-2011-4127", "CVE-2011-4622", "CVE-2012-0038", "CVE-2012-0055", "CVE-2012-0207", "CVE-2012-2100");
  script_bugtraq_id(50459, 51343, 51529);
  script_osvdb_id(77485, 77985, 78014, 78225, 78226, 79247);
  script_xref(name:"USN", value:"1384-1");

  script_name(english:"Ubuntu 10.04 LTS : linux-lts-backport-oneiric vulnerabilities (USN-1384-1)");
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
"A bug was discovered in the Linux kernel's calculation of OOM (Out of
memory) scores, that would result in the wrong process being killed. A
user could use this to kill the process with the highest OOM score,
even if that process belongs to another user or the system.
(CVE-2011-4097)

Paolo Bonzini discovered a flaw in Linux's handling of the SG_IO ioctl
command. A local user, or user in a VM could exploit this flaw to
bypass restrictions and gain read/write access to all data on the
affected block device. (CVE-2011-4127)

A flaw was found in KVM's Programmable Interval Timer (PIT). When a
virtual interrupt control is not available a local user could use this
to cause a denial of service by starting a timer. (CVE-2011-4622)

A flaw was discovered in the XFS filesystem. If a local user mounts a
specially crafted XFS image it could potential execute arbitrary code
on the system. (CVE-2012-0038)

Andy Whitcroft discovered a that the Overlayfs filesystem was not
doing the extended permission checks needed by cgroups and Linux
Security Modules (LSMs). A local user could exploit this to by-pass
security policy and access files that should not be accessible.
(CVE-2012-0055)

A flaw was found in the linux kernels IPv4 IGMP query processing. A
remote attacker could exploit this to cause a denial of service.
(CVE-2012-0207)

A flaw was found in the Linux kernel's ext4 file system when mounting
a corrupt filesystem. A user-assisted remote attacker could exploit
this flaw to cause a denial of service. (CVE-2012-2100).

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

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.0-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.0-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.0-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.0-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2012-2016 Canonical, Inc. / NASL script (C) 2012-2016 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"10.04", pkgname:"linux-image-3.0.0-16-generic", pkgver:"3.0.0-16.29~lucid1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-3.0.0-16-generic-pae", pkgver:"3.0.0-16.29~lucid1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-3.0.0-16-server", pkgver:"3.0.0-16.29~lucid1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-3.0.0-16-virtual", pkgver:"3.0.0-16.29~lucid1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.0-generic / linux-image-3.0-generic-pae / etc");
}
