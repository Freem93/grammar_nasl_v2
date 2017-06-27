#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1059-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51900);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/27 14:13:23 $");

  script_cve_id("CVE-2010-3304", "CVE-2010-3706", "CVE-2010-3707", "CVE-2010-3779", "CVE-2010-3780");
  script_bugtraq_id(41964, 43690);
  script_xref(name:"USN", value:"1059-1");

  script_name(english:"Ubuntu 10.04 LTS / 10.10 : dovecot vulnerabilities (USN-1059-1)");
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
"It was discovered that the ACL plugin in Dovecot would incorrectly
propagate ACLs to new mailboxes. A remote authenticated user could
possibly read new mailboxes that were created with the wrong ACL.
(CVE-2010-3304)

It was discovered that the ACL plugin in Dovecot would incorrectly
merge ACLs in certain circumstances. A remote authenticated user could
possibly bypass intended access restrictions and gain access to
mailboxes. (CVE-2010-3706, CVE-2010-3707)

It was discovered that the ACL plugin in Dovecot would incorrectly
grant the admin permission to owners of certain mailboxes. A remote
authenticated user could possibly bypass intended access restrictions
and gain access to mailboxes. (CVE-2010-3779)

It was discovered that Dovecot incorrecly handled the simultaneous
disconnect of a large number of sessions. A remote authenticated user
could use this flaw to cause Dovecot to crash, resulting in a denial
of service. (CVE-2010-3780).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-imapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-pop3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dovecot-postfix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mail-stack-delivery");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2016 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"dovecot", pkgver:"1.2.9-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"dovecot-common", pkgver:"1:1.2.9-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"dovecot-dbg", pkgver:"1.2.9-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"dovecot-dev", pkgver:"1.2.9-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"dovecot-imapd", pkgver:"1.2.9-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"dovecot-pop3d", pkgver:"1.2.9-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"dovecot-postfix", pkgver:"1.2.9-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"dovecot", pkgver:"1.2.12-1ubuntu8.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"dovecot-common", pkgver:"1:1.2.12-1ubuntu8.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"dovecot-dbg", pkgver:"1.2.12-1ubuntu8.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"dovecot-dev", pkgver:"1.2.12-1ubuntu8.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"dovecot-imapd", pkgver:"1.2.12-1ubuntu8.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"dovecot-pop3d", pkgver:"1.2.12-1ubuntu8.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"dovecot-postfix", pkgver:"1.2.12-1ubuntu8.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"mail-stack-delivery", pkgver:"1.2.12-1ubuntu8.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dovecot / dovecot-common / dovecot-dbg / dovecot-dev / etc");
}
