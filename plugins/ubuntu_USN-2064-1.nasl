#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2064-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71791);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/10/26 14:16:25 $");

  script_cve_id("CVE-2013-4345", "CVE-2013-4588", "CVE-2013-6378", "CVE-2013-6763");
  script_bugtraq_id(62740, 63707, 63744, 63886);
  script_osvdb_id(98017, 99673, 99999, 100294);
  script_xref(name:"USN", value:"2064-1");

  script_name(english:"Ubuntu 10.04 LTS : linux vulnerabilities (USN-2064-1)");
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
"Stephan Mueller reported an error in the Linux kernel's ansi cprng
random number generator. This flaw makes it easier for a local
attacker to break cryptographic protections. (CVE-2013-4345)

A flaw was discovered in the Linux kernel's IP Virtual Server (IP_VS)
support. A local user with the CAP_NET_ADMIN capability could exploit
this flaw to gain additional administrative privileges.
(CVE-2013-4588)

Nico Golde and Fabian Yamaguchi reported a flaw in the Linux kernel's
debugfs filesystem. An administrative local user could exploit this
flaw to cause a denial of service (OOPS). (CVE-2013-6378)

Nico Golde reported a flaw in the Linux kernel's userspace IO (uio)
driver. A local user could exploit this flaw to cause a denial of
service (memory corruption) or possibly gain privileges.
(CVE-2013-6763).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/05");
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

if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-55-386", pkgver:"2.6.32-55.117")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-55-generic", pkgver:"2.6.32-55.117")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-55-generic-pae", pkgver:"2.6.32-55.117")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-55-lpia", pkgver:"2.6.32-55.117")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-55-preempt", pkgver:"2.6.32-55.117")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-55-server", pkgver:"2.6.32-55.117")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-55-versatile", pkgver:"2.6.32-55.117")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-55-virtual", pkgver:"2.6.32-55.117")) flag++;

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
