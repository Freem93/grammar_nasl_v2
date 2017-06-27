#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-255-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21063);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/10/17 13:39:45 $");

  script_cve_id("CVE-2006-0225");
  script_osvdb_id(22692);
  script_xref(name:"USN", value:"255-1");

  script_name(english:"Ubuntu 4.10 / 5.04 / 5.10 : openssh vulnerability (USN-255-1)");
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
"Tomas Mraz discovered a shell code injection flaw in scp. When doing
local-to-local or remote-to-remote copying, scp expanded shell escape
characters. By tricking an user into using scp on a specially crafted
file name (which could also be caught by using an innocuous wild card
like '*'), an attacker could exploit this to execute arbitrary shell
commands with the privilege of that user.

Please be aware that scp is not designed to operate securely on
untrusted file names, since it needs to stay compatible with rcp.
Please use sftp for automated systems and potentially untrusted file
names.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssh-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2006-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4\.10|5\.04|5\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10 / 5.04 / 5.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"openssh-client", pkgver:"3.8.1p1-11ubuntu3.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"openssh-server", pkgver:"3.8.1p1-11ubuntu3.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"ssh", pkgver:"3.8.1p1-11ubuntu3.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"ssh-askpass-gnome", pkgver:"3.8.1p1-11ubuntu3.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openssh-client", pkgver:"3.9p1-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openssh-server", pkgver:"3.9p1-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"ssh", pkgver:"3.9p1-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"ssh-askpass-gnome", pkgver:"3.9p1-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openssh-client", pkgver:"4.1p1-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openssh-server", pkgver:"4.1p1-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"ssh", pkgver:"4.1p1-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"ssh-askpass-gnome", pkgver:"4.1p1-7ubuntu4.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh-client / openssh-server / ssh / ssh-askpass-gnome");
}
