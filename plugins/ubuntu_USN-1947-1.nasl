#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1947-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69812);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/10/26 14:16:25 $");

  script_cve_id("CVE-2012-5374", "CVE-2012-5375", "CVE-2013-1060", "CVE-2013-2140", "CVE-2013-2232", "CVE-2013-2234", "CVE-2013-4162", "CVE-2013-4163");
  script_bugtraq_id(56939, 56940, 60414, 60874, 60893, 61411, 61412, 62248);
  script_osvdb_id(88440, 88451, 94031, 94698, 94793, 95614, 95615, 97215);
  script_xref(name:"USN", value:"1947-1");

  script_name(english:"Ubuntu 12.04 LTS : linux-lts-quantal vulnerabilities (USN-1947-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A denial of service flaw was discovered in the Btrfs file system in
the Linux kernel. A local user could cause a denial of service by
creating a large number of files with names that have the same CRC32
hash value. (CVE-2012-5374)

A denial of service flaw was discovered in the Btrfs file system in
the Linux kernel. A local user could cause a denial of service
(prevent file creation) for a victim, by creating a file with a
specific CRC32C hash value in a directory important to the victim.
(CVE-2012-5375)

Vasily Kulikov discovered a flaw in the Linux Kernel's perf tool that
allows specified to be run as root. A local could exploit this flaw to
run commands as root when using the perf tool. user could exploit this
(CVE-2013-1060)

A flaw was discovered in the Xen subsystem of the Linux kernel when it
provides read-only access to a disk that supports TRIM or SCSI UNMAP
to a guest OS. A privileged user in the guest OS could exploit this
flaw to destroy data on the disk, even though the guest OS should not
be able to write to the disk. (CVE-2013-2140)

A flaw was discovered in the Linux kernel when an IPv6 socket is used
to connect to an IPv4 destination. An unprivileged local user could
exploit this flaw to cause a denial of service (system crash).
(CVE-2013-2232)

An information leak was discovered in the IPSec key_socket
implementation in the Linux kernel. An local user could exploit this
flaw to examine potentially sensitive information in kernel memory.
(CVE-2013-2234)

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
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected linux-image-3.5-generic package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.5-generic");
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

if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.5.0-40-generic", pkgver:"3.5.0-40.62~precise1")) flag++;

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
