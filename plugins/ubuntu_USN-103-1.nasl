#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-103-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20489);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/27 14:13:22 $");

  script_cve_id("CVE-2005-0400", "CVE-2005-0749", "CVE-2005-0750", "CVE-2005-0815", "CVE-2005-0839");
  script_xref(name:"USN", value:"103-1");

  script_name(english:"Ubuntu 4.10 : linux-source-2.6.8.1 vulnerabilities (USN-103-1)");
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
"Mathieu Lafon discovered an information leak in the ext2 file system
driver. When a new directory was created, the ext2 block written to
disk was not initialized, so that previous memory contents (which
could contain sensitive data like passwords) became visible on the raw
device. This is particularly important if the target device is
removable and thus can be read by users other than root.
(CAN-2005-0400)

Yichen Xie discovered a Denial of Service vulnerability in the ELF
loader. A specially crafted ELF library or executable could cause an
attempt to free an invalid pointer, which lead to a kernel crash.
(CAN-2005-0749)

Ilja van Sprundel discovered that the bluez_sock_create() function did
not check its 'protocol' argument for negative values. A local
attacker could exploit this to execute arbitrary code with root
privileges by creating a Bluetooth socket with a specially crafted
protocol number. (CAN-2005-0750)

Michal Zalewski discovered that the iso9660 file system driver fails
to check ranges properly in several cases. Mounting a specially
crafted CD-ROM may have caused a buffer overflow leading to a kernel
crash or even arbitrary code execution. (CAN-2005-0815)

Previous kernels did not restrict the use of the N_MOUSE line
discipline in the serial driver. This allowed an unprivileged user to
inject mouse movement and/or keystrokes (using the sunkbd driver) into
the input subsystem, taking over the console or an X session, where
another user is logged in. (CAN-2005-0839)

A Denial of Service vulnerability was found in the tmpfs driver, which
is commonly used to mount RAM disks below /dev/shm and /tmp. The
shm_nopage() did not properly verify its address argument, which could
be exploited by a local user to cause a kernel crash with invalid
addresses.
(http://linux.bkbits.net:8080/linux-2.6/cset@420551fbRlv9-QG6Gw9Lw_bKV
fPSsg).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-5-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-5-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-5-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-5-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-5-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-5-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-5-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-5-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-5-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-5-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-5-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-5-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-5-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-5-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-patch-debian-2.6.8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tree-2.6.8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2005-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"linux-doc-2.6.8.1", pkgver:"2.6.8.1-16.13")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5", pkgver:"2.6.8.1-16.13")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-386", pkgver:"2.6.8.1-16.13")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-686", pkgver:"2.6.8.1-16.13")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-686-smp", pkgver:"2.6.8.1-16.13")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-amd64-generic", pkgver:"2.6.8.1-16.13")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-amd64-k8", pkgver:"2.6.8.1-16.13")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-amd64-k8-smp", pkgver:"2.6.8.1-16.13")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-amd64-xeon", pkgver:"2.6.8.1-16.13")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-386", pkgver:"2.6.8.1-16.13")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-686", pkgver:"2.6.8.1-16.13")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-686-smp", pkgver:"2.6.8.1-16.13")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-amd64-generic", pkgver:"2.6.8.1-16.13")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-amd64-k8", pkgver:"2.6.8.1-16.13")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-amd64-k8-smp", pkgver:"2.6.8.1-16.13")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-amd64-xeon", pkgver:"2.6.8.1-16.13")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-patch-debian-2.6.8.1", pkgver:"2.6.8.1-16.13")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-source-2.6.8.1", pkgver:"2.6.8.1-16.13")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-tree-2.6.8.1", pkgver:"2.6.8.1-16.13")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc-2.6.8.1 / linux-headers-2.6.8.1-5 / etc");
}
