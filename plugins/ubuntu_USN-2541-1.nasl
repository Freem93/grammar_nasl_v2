#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2541-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82069);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/10/26 14:16:27 $");

  script_cve_id("CVE-2014-7822", "CVE-2014-9419", "CVE-2014-9683", "CVE-2015-1421");
  script_bugtraq_id(71794, 72356, 72643);
  script_osvdb_id(116259, 117716, 117810, 118625);
  script_xref(name:"USN", value:"2541-1");

  script_name(english:"Ubuntu 12.04 LTS : linux vulnerabilities (USN-2541-1)");
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
"The Linux kernel's splice system call did not correctly validate its
parameters. A local, unprivileged user could exploit this flaw to
cause a denial of service (system crash). (CVE-2014-7822)

A flaw was discovered in how Thread Local Storage (TLS) is handled by
the task switching function in the Linux kernel for x86_64 based
machines. A local user could exploit this flaw to bypass the Address
Space Layout Radomization (ASLR) protection mechanism. (CVE-2014-9419)

Dmitry Chernenkov discovered a buffer overflow in eCryptfs' encrypted
file name decoding. A local unprivileged user could exploit this flaw
to cause a denial of service (system crash) or potentially gain
administrative privileges. (CVE-2014-9683)

Sun Baoliang discovered a use after free flaw in the Linux kernel's
SCTP (Stream Control Transmission Protocol) subsystem during INIT
collisions. A remote attacker could exploit this flaw to cause a
denial of service (system crash) or potentially escalate their
privileges on the system. (CVE-2015-1421).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-highbank");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2015-2016 Canonical, Inc. / NASL script (C) 2015-2016 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-79-generic", pkgver:"3.2.0-79.115")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-79-generic-pae", pkgver:"3.2.0-79.115")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-79-highbank", pkgver:"3.2.0-79.115")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-79-virtual", pkgver:"3.2.0-79.115")) flag++;

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
