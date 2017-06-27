#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2285-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76564);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/07 14:54:25 $");

  script_cve_id("CVE-2014-0131", "CVE-2014-1739", "CVE-2014-3917", "CVE-2014-4014", "CVE-2014-4027", "CVE-2014-4608", "CVE-2014-4943");
  script_bugtraq_id(66101, 67699, 67985, 67988, 68048, 68214, 68683);
  script_osvdb_id(107819, 108001, 108026, 108489);
  script_xref(name:"USN", value:"2285-1");

  script_name(english:"Ubuntu 12.04 LTS : linux-lts-quantal vulnerabilities (USN-2285-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sasha Levin reported a flaw in the Linux kernel's point-to-point
protocol (PPP) when used with the Layer Two Tunneling Protocol (L2TP).
A local user could exploit this flaw to gain administrative
privileges. (CVE-2014-4943)

Michael S. Tsirkin discovered an information leak in the Linux
kernel's segmentation of skbs when using the zerocopy feature of
vhost-net. A local attacker could exploit this flaw to gain
potentially sensitive information from kernel memory. (CVE-2014-0131)

Salva Peiro discovered an information leak in the Linux kernel's
media- device driver. A local attacker could exploit this flaw to
obtain sensitive information from kernel memory. (CVE-2014-1739)

An flaw was discovered in the Linux kernel's audit subsystem when
auditing certain syscalls. A local attacker could exploit this flaw to
obtain potentially sensitive single-bit values from kernel memory or
cause a denial of service (OOPS). (CVE-2014-3917)

A flaw was discovered in the Linux kernel's implementation of user
namespaces with respect to inode permissions. A local user could
exploit this flaw by creating a user namespace to gain administrative
privileges. (CVE-2014-4014)

An information leak was discovered in the rd_mcp backend of the iSCSI
target subsystem in the Linux kernel. A local user could exploit this
flaw to obtain sensitive information from ramdisk_mcp memory by
leveraging access to a SCSI initiator. (CVE-2014-4027)

Don Bailey discovered a flaw in the LZO decompress algorithm used by
the Linux kernel. An attacker could exploit this flaw to cause a
denial of service (memory corruption or OOPS). (CVE-2014-4608).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected linux-image-3.5-generic package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.5-generic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/17");
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

if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.5.0-54-generic", pkgver:"3.5.0-54.81~precise1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.5-generic");
}
