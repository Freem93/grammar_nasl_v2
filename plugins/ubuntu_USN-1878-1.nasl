#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1878-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66902);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/10/26 14:05:59 $");

  script_cve_id("CVE-2013-0160", "CVE-2013-2146", "CVE-2013-3076", "CVE-2013-3222", "CVE-2013-3223", "CVE-2013-3224", "CVE-2013-3225", "CVE-2013-3227", "CVE-2013-3228", "CVE-2013-3229", "CVE-2013-3231", "CVE-2013-3232", "CVE-2013-3234", "CVE-2013-3235");
  script_osvdb_id(89143, 92656, 92657, 92660, 92661, 92663, 92664, 92666, 92667, 92668, 92669, 92670, 93906);
  script_xref(name:"USN", value:"1878-1");

  script_name(english:"Ubuntu 12.04 LTS : linux vulnerabilities (USN-1878-1)");
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
"An information leak was discovered in the Linux kernel when inotify is
used to monitor the /dev/ptmx device. A local user could exploit this
flaw to discover keystroke timing and potentially discover sensitive
information like password length. (CVE-2013-0160)

A flaw was discovered in the Linux kernel's perf events subsystem for
Intel Sandy Bridge and Ivy Bridge processors. A local user could
exploit this flaw to cause a denial of service (system crash).
(CVE-2013-2146)

An information leak was discovered in the Linux kernel's crypto API. A
local user could exploit this flaw to examine potentially sensitive
information from the kernel's stack memory. (CVE-2013-3076)

An information leak was discovered in the Linux kernel's rcvmsg path
for ATM (Asynchronous Transfer Mode). A local user could exploit this
flaw to examine potentially sensitive information from the kernel's
stack memory. (CVE-2013-3222)

An information leak was discovered in the Linux kernel's recvmsg path
for ax25 address family. A local user could exploit this flaw to
examine potentially sensitive information from the kernel's stack
memory. (CVE-2013-3223)

An information leak was discovered in the Linux kernel's recvmsg path
for the bluetooth address family. A local user could exploit this flaw
to examine potentially sensitive information from the kernel's stack
memory. (CVE-2013-3224)

An information leak was discovered in the Linux kernel's bluetooth
rfcomm protocol support. A local user could exploit this flaw to
examine potentially sensitive information from the kernel's stack
memory. (CVE-2013-3225)

An information leak was discovered in the Linux kernel's CAIF protocol
implementation. A local user could exploit this flaw to examine
potentially sensitive information from the kernel's stack memory.
(CVE-2013-3227)

An information leak was discovered in the Linux kernel's IRDA
(infrared) support subsystem. A local user could exploit this flaw to
examine potentially sensitive information from the kernel's stack
memory. (CVE-2013-3228)

An information leak was discovered in the Linux kernel's s390 - z/VM
support. A local user could exploit this flaw to examine potentially
sensitive information from the kernel's stack memory. (CVE-2013-3229)

An information leak was discovered in the Linux kernel's llc (Logical
Link Layer 2) support. A local user could exploit this flaw to examine
potentially sensitive information from the kernel's stack memory.
(CVE-2013-3231)

An information leak was discovered in the Linux kernel's receive
message handling for the netrom address family. A local user could
exploit this flaw to obtain sensitive information from the kernel's
stack memory. (CVE-2013-3232)

An information leak was discovered in the Linux kernel's Rose X.25
protocol layer. A local user could exploit this flaw to examine
potentially sensitive information from the kernel's stack memory.
(CVE-2013-3234)

An information leak was discovered in the Linux kernel's TIPC
(Transparent Inter Process Communication) protocol implementation. A
local user could exploit this flaw to examine potentially sensitive
information from the kernel's stack memory. (CVE-2013-3235).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-highbank");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/16");
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

if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-48-generic", pkgver:"3.2.0-48.74")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-48-generic-pae", pkgver:"3.2.0-48.74")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-48-highbank", pkgver:"3.2.0-48.74")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-48-virtual", pkgver:"3.2.0-48.74")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.2-generic / linux-image-3.2-generic-pae / etc");
}
