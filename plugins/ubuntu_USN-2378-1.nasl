#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2378-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78258);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/10/26 14:16:26 $");

  script_cve_id("CVE-2014-3181", "CVE-2014-3184", "CVE-2014-3185", "CVE-2014-3186", "CVE-2014-3631", "CVE-2014-6410", "CVE-2014-6416", "CVE-2014-6417", "CVE-2014-6418");
  script_bugtraq_id(69763, 69768, 69779, 69781, 69799, 69805, 70095);
  script_osvdb_id(110567, 110568, 110569, 110570, 110571, 110572, 110732, 111406, 111409, 111430);
  script_xref(name:"USN", value:"2378-1");

  script_name(english:"Ubuntu 12.04 LTS : linux-lts-trusty vulnerabilities (USN-2378-1)");
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
"Steven Vittitoe reported multiple stack buffer overflows in Linux
kernel's magicmouse HID driver. A physically proximate attacker could
exploit this flaw to cause a denial of service (system crash) or
possibly execute arbitrary code via specially crafted devices.
(CVE-2014-3181)

Ben Hawkes reported some off by one errors for report descriptors in
the Linux kernel's HID stack. A physically proximate attacker could
exploit these flaws to cause a denial of service (out-of-bounds write)
via a specially crafted device. (CVE-2014-3184)

Several bounds check flaws allowing for buffer overflows were
discovered in the Linux kernel's Whiteheat USB serial driver. A
physically proximate attacker could exploit these flaws to cause a
denial of service (system crash) via a specially crafted device.
(CVE-2014-3185)

Steven Vittitoe reported a buffer overflow in the Linux kernel's
PicoLCD HID device driver. A physically proximate attacker could
exploit this flaw to cause a denial of service (system crash) or
possibly execute arbitrary code via a specially craft device.
(CVE-2014-3186)

A flaw was discovered in the Linux kernel's associative-array garbage
collection implementation. A local user could exploit this flaw to
cause a denial of service (system crash) or possibly have other
unspecified impact by using keyctl operations. (CVE-2014-3631)

A flaw was discovered in the Linux kernel's UDF filesystem (used on
some CD-ROMs and DVDs) when processing indirect ICBs. An attacker who
can cause CD, DVD or image file with a specially crafted inode to be
mounted can cause a denial of service (infinite loop or stack
consumption). (CVE-2014-6410)

James Eckersall discovered a buffer overflow in the Ceph filesystem in
the Linux kernel. A remote attacker could exploit this flaw to cause a
denial of service (memory consumption and panic) or possibly have
other unspecified impact via a long unencrypted auth ticket.
(CVE-2014-6416)

James Eckersall discovered a flaw in the handling of memory allocation
failures in the Ceph filesystem. A remote attacker could exploit this
flaw to cause a denial of service (system crash) or possibly have
unspecified other impact. (CVE-2014-6417)

James Eckersall discovered a flaw in how the Ceph filesystem validates
auth replies. A remote attacker could exploit this flaw to cause a
denial of service (system crash) or possibly have other unspecified
impact. (CVE-2014-6418).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected linux-image-3.13-generic and / or
linux-image-3.13-generic-lpae packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/11");
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
if (! ereg(pattern:"^(12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.13.0-37-generic", pkgver:"3.13.0-37.64~precise1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.13.0-37-generic-lpae", pkgver:"3.13.0-37.64~precise1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.13-generic / linux-image-3.13-generic-lpae");
}
