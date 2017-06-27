#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-95-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20721);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/01 21:21:53 $");

  script_cve_id("CVE-2005-0209", "CVE-2005-0210", "CVE-2005-0384", "CVE-2005-0529", "CVE-2005-0530", "CVE-2005-0531", "CVE-2005-0532", "CVE-2005-0736");
  script_xref(name:"USN", value:"95-1");

  script_name(english:"Ubuntu 4.10 : linux-source-2.6.8.1 vulnerabilities (USN-95-1)");
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
"A remote Denial of Service vulnerability was discovered in the
Netfilter IP packet handler. This allowed a remote attacker to crash
the machine by sending specially crafted IP packet fragments.
(CAN-2005-0209)

The Netfilter code also contained a memory leak. Certain locally
generated packet fragments are reassembled twice, which caused a
double allocation of a data structure. This could be locally exploited
to crash the machine due to kernel memory exhaustion. (CAN-2005-0210)

Ben Martel and Stephen Blackheath found a remote Denial of Service
vulnerability in the PPP driver. This allowed a malicious pppd client
to crash the server machine. (CAN-2005-0384)

Georgi Guninski discovered a buffer overflow in the ATM driver. The
atm_get_addr() function does not validate its arguments sufficiently,
which could allow a local attacker to overwrite large portions of
kernel memory by supplying a negative length argument. This could
eventually lead to arbitrary code execution. (CAN-2005-0531)

Georgi Guninski also discovered three other integer comparison
problems in the TTY layer, in the /proc interface and the ReiserFS
driver. However, the previous Ubuntu security update (kernel version
2.6.8.1-16.11) already contained a patch which checks the arguments to
these functions at a higher level and thus prevents these flaws from
being exploited. (CAN-2005-0529, CAN-2005-0530, CAN-2005-0532)

Georgi Guninski discovered an integer overflow in the sys_epoll_wait()
function which allowed local users to overwrite the first few kB of
physical memory. However, very few applications actually use this
space (dosemu is a notable exception), but potentially this could lead
to privilege escalation. (CAN-2005-0736)

Eric Anholt discovered a race condition in the Radeon DRI driver. In
some cases this allowed a local user with DRI privileges on a Radeon
card to execute arbitrary code with root privileges.

Finally this update fixes a regression in the NFS server driver which
was introduced in the previous security update (kernel version
2.6.8.1-16.11). We apologize for the inconvenience.
(https://bugzilla.ubuntulinux.org/show_bug.cgi?id=6749)

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20, 399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/15");
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

if (ubuntu_check(osver:"4.10", pkgname:"linux-doc-2.6.8.1", pkgver:"2.6.8.1-16.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5", pkgver:"2.6.8.1-16.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-386", pkgver:"2.6.8.1-16.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-686", pkgver:"2.6.8.1-16.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-686-smp", pkgver:"2.6.8.1-16.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-amd64-generic", pkgver:"2.6.8.1-16.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-amd64-k8", pkgver:"2.6.8.1-16.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-amd64-k8-smp", pkgver:"2.6.8.1-16.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-amd64-xeon", pkgver:"2.6.8.1-16.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-386", pkgver:"2.6.8.1-16.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-686", pkgver:"2.6.8.1-16.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-686-smp", pkgver:"2.6.8.1-16.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-amd64-generic", pkgver:"2.6.8.1-16.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-amd64-k8", pkgver:"2.6.8.1-16.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-amd64-k8-smp", pkgver:"2.6.8.1-16.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-amd64-xeon", pkgver:"2.6.8.1-16.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-patch-debian-2.6.8.1", pkgver:"2.6.8.1-16.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-source-2.6.8.1", pkgver:"2.6.8.1-16.12")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-tree-2.6.8.1", pkgver:"2.6.8.1-16.12")) flag++;

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
