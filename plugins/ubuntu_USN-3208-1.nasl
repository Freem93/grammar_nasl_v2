#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3208-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97322);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/03/07 17:25:25 $");

  script_cve_id("CVE-2016-10088", "CVE-2016-9191", "CVE-2016-9588", "CVE-2017-2583", "CVE-2017-2584", "CVE-2017-5549", "CVE-2017-6074");
  script_osvdb_id(146761, 148443, 148861, 150064, 150690, 150782, 152302);
  script_xref(name:"USN", value:"3208-1");

  script_name(english:"Ubuntu 16.04 LTS : linux, linux-snapdragon vulnerabilities (USN-3208-1)");
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
"It was discovered that the generic SCSI block layer in the Linux
kernel did not properly restrict write operations in certain
situations. A local attacker could use this to cause a denial of
service (system crash) or possibly gain administrative privileges.
(CVE-2016-10088)

CAI Qian discovered that the sysctl implementation in the Linux kernel
did not properly perform reference counting in some situations. An
unprivileged attacker could use this to cause a denial of service
(system hang). (CVE-2016-9191)

Jim Mattson discovered that the KVM implementation in the Linux kernel
mismanages the #BP and #OF exceptions. A local attacker in a guest
virtual machine could use this to cause a denial of service (guest OS
crash). (CVE-2016-9588)

Andy Lutomirski and Willy Tarreau discovered that the KVM
implementation in the Linux kernel did not properly emulate
instructions on the SS segment register. A local attacker in a guest
virtual machine could use this to cause a denial of service (guest OS
crash) or possibly gain administrative privileges in the guest OS.
(CVE-2017-2583)

Dmitry Vyukov discovered that the KVM implementation in the Linux
kernel improperly emulated certain instructions. A local attacker
could use this to obtain sensitive information (kernel memory).
(CVE-2017-2584)

It was discovered that the KLSI KL5KUSB105 serial-to-USB device driver
in the Linux kernel did not properly initialize memory related to
logging. A local attacker could use this to expose sensitive
information (kernel memory). (CVE-2017-5549)

Andrey Konovalov discovered a use-after-free vulnerability in the DCCP
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly gain
administrative privileges. (CVE-2017-6074).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2017 Canonical, Inc. / NASL script (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1048-snapdragon", pkgver:"4.4.0-1048.52")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-64-generic", pkgver:"4.4.0-64.85")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-64-generic-lpae", pkgver:"4.4.0-64.85")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-64-lowlatency", pkgver:"4.4.0-64.85")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic", pkgver:"4.4.0.64.68")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-generic-lpae", pkgver:"4.4.0.64.68")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-lowlatency", pkgver:"4.4.0.64.68")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"linux-image-snapdragon", pkgver:"4.4.0.1048.40")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.4-generic / linux-image-4.4-generic-lpae / etc");
}
