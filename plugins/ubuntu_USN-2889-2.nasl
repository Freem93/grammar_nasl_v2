#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2889-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88523);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/01 20:56:52 $");

  script_cve_id("CVE-2013-7446", "CVE-2015-7513", "CVE-2015-7990", "CVE-2015-8374", "CVE-2015-8787");
  script_osvdb_id(127759, 130525, 130832, 132618, 133747);
  script_xref(name:"USN", value:"2889-2");

  script_name(english:"Ubuntu 14.04 LTS : linux-lts-vivid vulnerabilities (USN-2889-2)");
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
"It was discovered that a use-after-free vulnerability existed in the
AF_UNIX implementation in the Linux kernel. A local attacker could use
crafted epoll_ctl calls to cause a denial of service (system crash) or
expose sensitive information. (CVE-2013-7446)

It was discovered that the KVM implementation in the Linux kernel did
not properly restore the values of the Programmable Interrupt Timer
(PIT). A user-assisted attacker in a KVM guest could cause a denial of
service in the host (system crash). (CVE-2015-7513)

Sasha Levin discovered that the Reliable Datagram Sockets (RDS)
implementation in the Linux kernel had a race condition when checking
whether a socket was bound or not. A local attacker could use this to
cause a denial of service (system crash). (CVE-2015-7990)

It was discovered that the Btrfs implementation in the Linux kernel
incorrectly handled compressed inline extants on truncation. A local
attacker could use this to expose sensitive information.
(CVE-2015-8374)

It was discovered that the netfilter Network Address Translation (NAT)
implementation did not ensure that data structures were initialized
when handling IPv4 addresses. An attacker could use this to cause a
denial of service (system crash). (CVE-2015-8787).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected linux-image-3.19-generic,
linux-image-3.19-generic-lpae and / or linux-image-3.19-lowlatency
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.19-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.19-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.19-lowlatency");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/02");
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
if (! ereg(pattern:"^(14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.19.0-49-generic", pkgver:"3.19.0-49.55~14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.19.0-49-generic-lpae", pkgver:"3.19.0-49.55~14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-3.19.0-49-lowlatency", pkgver:"3.19.0-49.55~14.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.19-generic / linux-image-3.19-generic-lpae / etc");
}
