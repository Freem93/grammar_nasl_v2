#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1912-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69121);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/10/26 14:05:59 $");

  script_cve_id("CVE-2013-2164", "CVE-2013-2232", "CVE-2013-2234", "CVE-2013-2237", "CVE-2013-2851");
  script_bugtraq_id(60375, 60409, 60874, 60893, 60953);
  script_osvdb_id(94035);
  script_xref(name:"USN", value:"1912-1");

  script_name(english:"Ubuntu 10.04 LTS : linux vulnerabilities (USN-1912-1)");
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
"Jonathan Salwan discovered an information leak in the Linux kernel's
cdrom driver. A local user can exploit this leak to obtain sensitive
information from kernel memory if the CD-ROM drive is malfunctioning.
(CVE-2013-2164)

A flaw was discovered in the Linux kernel when an IPv6 socket is used
to connect to an IPv4 destination. An unprivileged local user could
exploit this flaw to cause a denial of service (system crash).
(CVE-2013-2232)

An information leak was discovered in the IPSec key_socket
implementation in the Linux kernel. An local user could exploit this
flaw to examine potentially sensitive information in kernel memory.
(CVE-2013-2234)

An information leak was discovered in the Linux kernel's IPSec
key_socket when using the notify_policy interface. A local user could
exploit this flaw to examine potentially sensitive information in
kernel memory. (CVE-2013-2237)

Kees Cook discovered a format string vulnerability in the Linux
kernel's disk block layer. A local user with administrator privileges
could exploit this flaw to gain kernel privileges. (CVE-2013-2851).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/30");
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
if (! ereg(pattern:"^(10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-50-386", pkgver:"2.6.32-50.112")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-50-generic", pkgver:"2.6.32-50.112")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-50-generic-pae", pkgver:"2.6.32-50.112")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-50-lpia", pkgver:"2.6.32-50.112")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-50-preempt", pkgver:"2.6.32-50.112")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-50-server", pkgver:"2.6.32-50.112")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-50-versatile", pkgver:"2.6.32-50.112")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-50-virtual", pkgver:"2.6.32-50.112")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-2.6-386 / linux-image-2.6-generic / etc");
}
