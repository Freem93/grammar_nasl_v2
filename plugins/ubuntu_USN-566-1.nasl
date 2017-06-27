#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-566-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29922);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/27 14:29:18 $");

  script_cve_id("CVE-2007-4752");
  script_bugtraq_id(25628);
  script_osvdb_id(43371);
  script_xref(name:"USN", value:"566-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 / 7.10 : openssh vulnerability (USN-566-1)");
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
"Jan Pechanec discovered that ssh would forward trusted X11 cookies
when untrusted cookie generation failed. This could lead to unintended
privileges being forwarded to a remote host.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssh-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ssh-krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2008-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|6\.10|7\.04|7\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 6.10 / 7.04 / 7.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"openssh-client", pkgver:"1:4.2p1-7ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openssh-server", pkgver:"4.2p1-7ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ssh", pkgver:"4.2p1-7ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ssh-askpass-gnome", pkgver:"4.2p1-7ubuntu3.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"openssh-client", pkgver:"1:4.3p2-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"openssh-server", pkgver:"4.3p2-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"ssh", pkgver:"4.3p2-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"ssh-askpass-gnome", pkgver:"4.3p2-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"openssh-client", pkgver:"1:4.3p2-8ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"openssh-server", pkgver:"4.3p2-8ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"ssh", pkgver:"4.3p2-8ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"ssh-askpass-gnome", pkgver:"4.3p2-8ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"ssh-krb5", pkgver:"4.3p2-8ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openssh-client", pkgver:"1:4.6p1-5ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openssh-server", pkgver:"4.6p1-5ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ssh", pkgver:"4.6p1-5ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ssh-askpass-gnome", pkgver:"4.6p1-5ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ssh-krb5", pkgver:"4.6p1-5ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh-client / openssh-server / ssh / ssh-askpass-gnome / etc");
}
