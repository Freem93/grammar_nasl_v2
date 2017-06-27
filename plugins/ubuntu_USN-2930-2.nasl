#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2930-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89935);
  script_version("$Revision: 2.10 $");
  script_cvs_date("$Date: 2017/03/08 15:07:21 $");

  script_cve_id("CVE-2015-7566", "CVE-2015-8767", "CVE-2016-0723", "CVE-2016-2384", "CVE-2016-2782", "CVE-2016-3134", "CVE-2016-3135");
  script_osvdb_id(132748, 132811, 133409, 134538, 135143, 135678, 135870);
  script_xref(name:"USN", value:"2930-2");

  script_name(english:"Ubuntu 14.04 LTS : linux-lts-wily vulnerabilities (USN-2930-2)");
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
"Ben Hawkes discovered that the Linux netfilter implementation did not
correctly perform validation when handling IPT_SO_SET_REPLACE events.
A local unprivileged attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code with
administrative privileges. (CVE-2016-3134)

Ben Hawkes discovered an integer overflow in the Linux netfilter
implementation. On systems running 32 bit kernels, a local
unprivileged attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code with administrative
privileges. (CVE-2016-3135)

Ralf Spenneberg discovered that the USB driver for Clie devices in the
Linux kernel did not properly sanity check the endpoints reported by
the device. An attacker with physical access could cause a denial of
service (system crash). (CVE-2015-7566)

It was discovered that a race condition existed when handling
heartbeat- timeout events in the SCTP implementation of the Linux
kernel. A remote attacker could use this to cause a denial of service.
(CVE-2015-8767)

It was discovered that a race condition existed in the ioctl handler
for the TTY driver in the Linux kernel. A local attacker could use
this to cause a denial of service (system crash) or expose sensitive
information. (CVE-2016-0723)

Andrey Konovalov discovered that the ALSA USB MIDI driver incorrectly
performed a double-free. A local attacker with physical access could
use this to cause a denial of service (system crash) or possibly
execute arbitrary code with administrative privileges. (CVE-2016-2384)

Ralf Spenneberg discovered that the USB driver for Treo devices in the
Linux kernel did not properly sanity check the endpoints reported by
the device. An attacker with physical access could cause a denial of
service (system crash). (CVE-2016-2782).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected linux-image-4.2-generic,
linux-image-4.2-generic-lpae and / or linux-image-4.2-lowlatency
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.2-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.2-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.2-lowlatency");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016-2017 Canonical, Inc. / NASL script (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"linux-image-4.2.0-34-generic", pkgver:"4.2.0-34.39~14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-4.2.0-34-generic-lpae", pkgver:"4.2.0-34.39~14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-4.2.0-34-lowlatency", pkgver:"4.2.0-34.39~14.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.2-generic / linux-image-4.2-generic-lpae / etc");
}
