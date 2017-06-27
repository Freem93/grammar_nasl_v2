#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1796-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65871);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/10/26 14:05:58 $");

  script_cve_id("CVE-2013-0228", "CVE-2013-0914", "CVE-2013-1767", "CVE-2013-1792", "CVE-2013-2546", "CVE-2013-2547", "CVE-2013-2548");
  script_bugtraq_id(57940, 58368);
  script_xref(name:"USN", value:"1796-1");

  script_name(english:"Ubuntu 12.10 : linux vulnerabilities (USN-1796-1)");
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
"Andrew Jones discovered a flaw with the xen_iret function in Linux
kernel's Xen virtualizeation. In the 32-bit Xen paravirt platform an
unprivileged guest OS user could exploit this flaw to cause a denial
of service (crash the system) or gain guest OS privilege.
(CVE-2013-0228)

Emese Revfy discovered that in the Linux kernel signal handlers could
leak address information across an exec, making it possible to by pass
ASLR (Address Space Layout Randomization). A local user could use this
flaw to by pass ASLR to reliably deliver an exploit payload that would
otherwise be stopped (by ASLR). (CVE-2013-0914)

A memory use after free error was discover in the Linux kernel's tmpfs
filesystem. A local user could exploit this flaw to gain privileges or
cause a denial of service (system crash). (CVE-2013-1767)

Mateusz Guzik discovered a race in the Linux kernel's keyring. A local
user could exploit this flaw to cause a denial of service (system
crash). (CVE-2013-1792)

Mathias Krause discovered a memory leak in the Linux kernel's crypto
report API. A local user with CAP_NET_ADMIN could exploit this leak to
examine some of the kernel's stack memory. (CVE-2013-2546)

Mathias Krause discovered a memory leak in the Linux kernel's crypto
report API. A local user with CAP_NET_ADMIN could exploit this leak to
examine some of the kernel's heap memory. (CVE-2013-2547)

Mathias Krause discovered information leaks in the Linux kernel's
crypto algorithm report API. A local user could exploit these flaws to
leak kernel stack and heap memory contents. (CVE-2013-2548).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected linux-image-3.5-generic and / or
linux-image-3.5-highbank packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.5-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.5-highbank");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/09");
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
if (! ereg(pattern:"^(12\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.10", pkgname:"linux-image-3.5.0-27-generic", pkgver:"3.5.0-27.46")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"linux-image-3.5.0-27-highbank", pkgver:"3.5.0-27.46")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.5-generic / linux-image-3.5-highbank");
}
