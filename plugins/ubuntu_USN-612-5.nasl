#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-612-5. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32359);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:29:19 $");

  script_cve_id("CVE-2008-0166", "CVE-2008-2285");
  script_bugtraq_id(29179);
  script_osvdb_id(45503);
  script_xref(name:"USN", value:"612-5");

  script_name(english:"Ubuntu 7.04 / 7.10 / 8.04 LTS : openssh update (USN-612-5)");
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
"Matt Zimmerman discovered that entries in ~/.ssh/authorized_keys with
options (such as 'no-port-forwarding' or forced commands) were ignored
by the new ssh-vulnkey tool introduced in OpenSSH (see USN-612-2).
This could cause some compromised keys not to be listed in
ssh-vulnkey's output.

This update also adds more information to ssh-vulnkey's manual page.

A weakness has been discovered in the random number generator used by
OpenSSL on Debian and Ubuntu systems. As a result of this weakness,
certain encryption keys are much more common than they should be, such
that an attacker could guess the key through a brute-force attack
given minimal knowledge of the system. This particularly affects the
use of encryption keys in OpenSSH, OpenVPN and SSL certificates.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssh-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssh-client-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ssh-krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/14");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/16");
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
if (! ereg(pattern:"^(7\.04|7\.10|8\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 7.04 / 7.10 / 8.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"7.04", pkgname:"openssh-client", pkgver:"1:4.3p2-8ubuntu1.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"openssh-client-udeb", pkgver:"1:4.3p2-8ubuntu1.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"openssh-server", pkgver:"4.3p2-8ubuntu1.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"ssh", pkgver:"4.3p2-8ubuntu1.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"ssh-askpass-gnome", pkgver:"4.3p2-8ubuntu1.4")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"ssh-krb5", pkgver:"4.3p2-8ubuntu1.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openssh-client", pkgver:"1:4.6p1-5ubuntu0.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openssh-client-udeb", pkgver:"1:4.6p1-5ubuntu0.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openssh-server", pkgver:"4.6p1-5ubuntu0.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ssh", pkgver:"4.6p1-5ubuntu0.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ssh-askpass-gnome", pkgver:"4.6p1-5ubuntu0.5")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ssh-krb5", pkgver:"4.6p1-5ubuntu0.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openssh-client", pkgver:"1:4.7p1-8ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openssh-client-udeb", pkgver:"1:4.7p1-8ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openssh-server", pkgver:"4.7p1-8ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ssh", pkgver:"4.7p1-8ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ssh-askpass-gnome", pkgver:"4.7p1-8ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ssh-krb5", pkgver:"4.7p1-8ubuntu1.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh-client / openssh-client-udeb / openssh-server / ssh / etc");
}
