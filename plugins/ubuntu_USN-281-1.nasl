#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-281-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21375);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/10/26 14:26:00 $");

  script_cve_id("CVE-2006-0557", "CVE-2006-1052", "CVE-2006-1055", "CVE-2006-1066", "CVE-2006-1242", "CVE-2006-1342", "CVE-2006-1343", "CVE-2006-1368", "CVE-2006-1525");
  script_osvdb_id(23895, 24041, 24071, 24098, 24137, 24443, 24715, 25232);
  script_xref(name:"USN", value:"281-1");

  script_name(english:"Ubuntu 5.04 / 5.10 : linux-source-2.6.10, linux-source-2.6.12 vulnerabilities (USN-281-1)");
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
"The sys_mbind() function did not properly verify the validity of the
'maxnod' argument. A local user could exploit this to trigger a buffer
overflow, which caused a kernel crash. (CVE-2006-0557)

The SELinux module did not correctly handle the tracer SID when a
process was already being traced. A local attacker could exploit this
to cause a kernel crash. (CVE-2006-1052)

Al Viro discovered a local Denial of Service in the sysfs write buffer
handling. By writing a block with a length exactly equal to the
processor's page size to any writable file in /sys, a local attacker
could cause a kernel crash. (CVE-2006-1055)

John Blackwood discovered a race condition with single-step debugging
multiple processes at the same time. A local attacker could exploit
this to crash the system. This only affects the amd64 platform.
(CVE-2006-1066)

Marco Ivaldi discovered a flaw in the handling of the ID number of IP
packets. This number was incremented after receiving unsolicited TCP
SYN-ACK packets. A remote attacker could exploit this to conduct port
scans with the 'Idle scan' method (nmap -sI), which bypassed intended
port scan protections. (CVE-2006-1242)

Pavel Kankovsky discovered that the getsockopt() function, when called
with an SO_ORIGINAL_DST argument, does not properly clear the returned
structure, so that a random piece of kernel memory is exposed to the
user. This could potentially reveal sensitive data like passwords or
encryption keys. (CVE-2006-1343)

A buffer overflow was discovered in the USB Gadget RNDIS
implementation. While creating a reply message, the driver did not
allocate enough memory for the reply structure. A remote attacker
could exploit this to cause a kernel crash. (CVE-2006-1368)

Alexandra Kossovsky discovered an invalid memory access in the
ip_route_input() function. By using the 'ip' command in a particular
way to retrieve multicast routes, a local attacker could exploit this
to crash the kernel. (CVE-2006-1525).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-patch-ubuntu-2.6.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-patch-ubuntu-2.6.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tree-2.6.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tree-2.6.12");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2006-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5\.04|5\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.04 / 5.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.04", pkgname:"linux-doc-2.6.10", pkgver:"2.6.10-34.17")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6", pkgver:"2.6.10-34.17")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6-386", pkgver:"2.6.10-34.17")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6-686", pkgver:"2.6.10-34.17")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6-686-smp", pkgver:"2.6.10-34.17")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6-amd64-generic", pkgver:"2.6.10-34.17")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6-amd64-k8", pkgver:"2.6.10-34.17")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6-amd64-k8-smp", pkgver:"2.6.10-34.17")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-6-amd64-xeon", pkgver:"2.6.10-34.17")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-6-386", pkgver:"2.6.10-34.17")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-6-686", pkgver:"2.6.10-34.17")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-6-686-smp", pkgver:"2.6.10-34.17")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-6-amd64-generic", pkgver:"2.6.10-34.17")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-6-amd64-k8", pkgver:"2.6.10-34.17")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-6-amd64-k8-smp", pkgver:"2.6.10-34.17")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-6-amd64-xeon", pkgver:"2.6.10-34.17")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-patch-ubuntu-2.6.10", pkgver:"2.6.10-34.17")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-source-2.6.10", pkgver:"2.6.10-34.17")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-tree-2.6.10", pkgver:"2.6.10-34.17")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-doc-2.6.12", pkgver:"2.6.12-10.32")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10", pkgver:"2.6.12-10.32")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-386", pkgver:"2.6.12-10.32")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-686", pkgver:"2.6.12-10.32")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-686-smp", pkgver:"2.6.12-10.32")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-amd64-generic", pkgver:"2.6.12-10.32")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-amd64-k8", pkgver:"2.6.12-10.32")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-amd64-k8-smp", pkgver:"2.6.12-10.32")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-headers-2.6.12-10-amd64-xeon", pkgver:"2.6.12-10.32")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-386", pkgver:"2.6.12-10.32")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-686", pkgver:"2.6.12-10.32")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-686-smp", pkgver:"2.6.12-10.32")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-amd64-generic", pkgver:"2.6.12-10.32")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-amd64-k8", pkgver:"2.6.12-10.32")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-amd64-k8-smp", pkgver:"2.6.12-10.32")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-image-2.6.12-10-amd64-xeon", pkgver:"2.6.12-10.32")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-patch-ubuntu-2.6.12", pkgver:"2.6.12-10.32")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-source-2.6.12", pkgver:"2.6.12-10.32")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"linux-tree-2.6.12", pkgver:"2.6.12-10.32")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc-2.6.10 / linux-doc-2.6.12 / linux-headers-2.6 / etc");
}
