#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3162-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96000);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2016/12/21 20:33:29 $");

  script_cve_id("CVE-2016-6213", "CVE-2016-7097", "CVE-2016-7425", "CVE-2016-8630", "CVE-2016-8633", "CVE-2016-8645", "CVE-2016-9313", "CVE-2016-9555");
  script_osvdb_id(141527, 142080, 143514, 144411, 146778, 147015, 147168, 147698);
  script_xref(name:"USN", value:"3162-2");

  script_name(english:"Ubuntu 16.10 : linux-raspi2 vulnerabilities (USN-3162-2)");
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
"CAI Qian discovered that shared bind mounts in a mount namespace
exponentially added entries without restriction to the Linux kernel's
mount table. A local attacker could use this to cause a denial of
service (system crash). (CVE-2016-6213)

Andreas Gruenbacher and Jan Kara discovered that the filesystem
implementation in the Linux kernel did not clear the setgid bit during
a setxattr call. A local attacker could use this to possibly elevate
group privileges. (CVE-2016-7097)

Marco Grassi discovered that the driver for Areca RAID Controllers in
the Linux kernel did not properly validate control messages. A local
attacker could use this to cause a denial of service (system crash) or
possibly gain privileges. (CVE-2016-7425)

It was discovered that the KVM implementation for x86/x86_64 in the
Linux kernel could dereference a NULL pointer. An attacker in a guest
virtual machine could use this to cause a denial of service (system
crash) in the KVM host. (CVE-2016-8630)

Eyal Itkin discovered that the IP over IEEE 1394 (FireWire)
implementation in the Linux kernel contained a buffer overflow when
handling fragmented packets. A remote attacker could use this to
possibly execute arbitrary code with administrative privileges.
(CVE-2016-8633)

Marco Grassi discovered that the TCP implementation in the Linux
kernel mishandles socket buffer (skb) truncation. A local attacker
could use this to cause a denial of service (system crash).
(CVE-2016-8645)

It was discovered that the keyring implementation in the Linux kernel
improperly handled crypto registration in conjunction with successful
key- type registration. A local attacker could use this to cause a
denial of service (system crash). (CVE-2016-9313)

Andrey Konovalov discovered that the SCTP implementation in the Linux
kernel improperly handled validation of incoming data. A remote
attacker could use this to cause a denial of service (system crash).
(CVE-2016-9555).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected linux-image-4.8-raspi2 and / or linux-image-raspi2
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.8-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/21");
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
if (! ereg(pattern:"^(16\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"16.10", pkgname:"linux-image-4.8.0-1021-raspi2", pkgver:"4.8.0-1021.24")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"linux-image-raspi2", pkgver:"4.8.0.1021.24")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.8-raspi2 / linux-image-raspi2");
}
