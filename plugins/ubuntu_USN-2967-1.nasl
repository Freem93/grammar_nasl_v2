#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2967-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91087);
  script_version("$Revision: 2.19 $");
  script_cvs_date("$Date: 2016/12/01 21:07:49 $");

  script_cve_id("CVE-2013-4312", "CVE-2015-1805", "CVE-2015-7515", "CVE-2015-7566", "CVE-2015-7833", "CVE-2015-8767", "CVE-2015-8812", "CVE-2016-0723", "CVE-2016-0774", "CVE-2016-0821", "CVE-2016-2069", "CVE-2016-2543", "CVE-2016-2544", "CVE-2016-2545", "CVE-2016-2546", "CVE-2016-2547", "CVE-2016-2548", "CVE-2016-2549", "CVE-2016-2782", "CVE-2016-2847");
  script_osvdb_id(122968, 128557, 130648, 132748, 132811, 133379, 133409, 133625, 134512, 134915, 134916, 134917, 134918, 134919, 134920, 135143, 135194, 135482);
  script_xref(name:"USN", value:"2967-1");

  script_name(english:"Ubuntu 12.04 LTS : linux vulnerabilities (USN-2967-1)");
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
"It was discovered that the Linux kernel did not properly enforce
rlimits for file descriptors sent over UNIX domain sockets. A local
attacker could use this to cause a denial of service. (CVE-2013-4312)

Ralf Spenneberg discovered that the Aiptek Tablet USB device driver in
the Linux kernel did not properly sanity check the endpoints reported
by the device. An attacker with physical access could cause a denial
of service (system crash). (CVE-2015-7515)

Ralf Spenneberg discovered that the USB driver for Clie devices in the
Linux kernel did not properly sanity check the endpoints reported by
the device. An attacker with physical access could cause a denial of
service (system crash). (CVE-2015-7566)

Ralf Spenneberg discovered that the usbvision driver in the Linux
kernel did not properly sanity check the interfaces and endpoints
reported by the device. An attacker with physical access could cause a
denial of service (system crash). (CVE-2015-7833)

It was discovered that a race condition existed when handling
heartbeat- timeout events in the SCTP implementation of the Linux
kernel. A remote attacker could use this to cause a denial of service.
(CVE-2015-8767)

Venkatesh Pottem discovered a use-after-free vulnerability in the
Linux kernel's CXGB3 driver. A local attacker could use this to cause
a denial of service (system crash) or possibly execute arbitrary code.
(CVE-2015-8812)

It was discovered that a race condition existed in the ioctl handler
for the TTY driver in the Linux kernel. A local attacker could use
this to cause a denial of service (system crash) or expose sensitive
information. (CVE-2016-0723)

It was discovered that the Linux kernel did not keep accurate track of
pipe buffer details when error conditions occurred, due to an
incomplete fix for CVE-2015-1805. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code with administrative privileges. (CVE-2016-0774)

Zach Riggle discovered that the Linux kernel's list poison feature did
not take into account the mmap_min_addr value. A local attacker could
use this to bypass the kernel's poison-pointer protection mechanism
while attempting to exploit an existing kernel vulnerability.
(CVE-2016-0821)

Andy Lutomirski discovered a race condition in the Linux kernel's
translation lookaside buffer (TLB) handling of flush events. A local
attacker could use this to cause a denial of service or possibly leak
sensitive information. (CVE-2016-2069)

Dmitry Vyukov discovered that the Advanced Linux Sound Architecture
(ALSA) framework did not verify that a FIFO was attached to a client
before attempting to clear it. A local attacker could use this to
cause a denial of service (system crash). (CVE-2016-2543)

Dmitry Vyukov discovered that a race condition existed in the Advanced
Linux Sound Architecture (ALSA) framework between timer setup and
closing of the client, resulting in a use-after-free. A local attacker
could use this to cause a denial of service. (CVE-2016-2544)

Dmitry Vyukov discovered a race condition in the timer handling
implementation of the Advanced Linux Sound Architecture (ALSA)
framework, resulting in a use-after-free. A local attacker could use
this to cause a denial of service (system crash). (CVE-2016-2545)

Dmitry Vyukov discovered race conditions in the Advanced Linux Sound
Architecture (ALSA) framework's timer ioctls leading to a
use-after-free. A local attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code.
(CVE-2016-2546)

Dmitry Vyukov discovered that the Advanced Linux Sound Architecture
(ALSA) framework's handling of high resolution timers did not properly
manage its data structures. A local attacker could use this to cause a
denial of service (system hang or crash) or possibly execute arbitrary
code. (CVE-2016-2547, CVE-2016-2548)

Dmitry Vyukov discovered that the Advanced Linux Sound Architecture
(ALSA) framework's handling of high resolution timers could lead to a
deadlock condition. A local attacker could use this to cause a denial
of service (system hang). (CVE-2016-2549)

Ralf Spenneberg discovered that the USB driver for Treo devices in the
Linux kernel did not properly sanity check the endpoints reported by
the device. An attacker with physical access could cause a denial of
service (system crash). (CVE-2016-2782)

It was discovered that the Linux kernel did not enforce limits on the
amount of data allocated to buffer pipes. A local attacker could use
this to cause a denial of service (resource exhaustion).
(CVE-2016-2847).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-highbank");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016 Canonical, Inc. / NASL script (C) 2016 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-102-generic", pkgver:"3.2.0-102.142")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-102-generic-pae", pkgver:"3.2.0-102.142")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-102-highbank", pkgver:"3.2.0-102.142")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-102-virtual", pkgver:"3.2.0-102.142")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.2-generic / linux-image-3.2-generic-pae / etc");
}
