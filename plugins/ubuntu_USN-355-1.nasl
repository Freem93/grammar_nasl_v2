#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-355-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27935);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/01 21:07:50 $");

  script_cve_id("CVE-2006-4924", "CVE-2006-5051", "CVE-2008-4109");
  script_bugtraq_id(20216);
  script_osvdb_id(29152, 29264);
  script_xref(name:"USN", value:"355-1");

  script_name(english:"Ubuntu 5.04 / 5.10 / 6.06 LTS : openssh vulnerabilities (USN-355-1)");
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
"Tavis Ormandy discovered that the SSH daemon did not properly handle
authentication packets with duplicated blocks. By sending specially
crafted packets, a remote attacker could exploit this to cause the ssh
daemon to drain all available CPU resources until the login grace time
expired. (CVE-2006-4924)

Mark Dowd discovered a race condition in the server's signal handling.
A remote attacker could exploit this to crash the server.
(CVE-2006-5051).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssh-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2006-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5\.04|5\.10|6\.06)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.04 / 5.10 / 6.06", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.04", pkgname:"openssh-client", pkgver:"3.9p1-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openssh-server", pkgver:"1:3.9p1-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"ssh", pkgver:"3.9p1-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"ssh-askpass-gnome", pkgver:"3.9p1-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openssh-client", pkgver:"4.1p1-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openssh-server", pkgver:"1:4.1p1-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"ssh", pkgver:"4.1p1-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"ssh-askpass-gnome", pkgver:"4.1p1-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openssh-client", pkgver:"4.2p1-7ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openssh-server", pkgver:"1:4.2p1-7ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ssh", pkgver:"4.2p1-7ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ssh-askpass-gnome", pkgver:"4.2p1-7ubuntu3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh-client / openssh-server / ssh / ssh-askpass-gnome");
}
