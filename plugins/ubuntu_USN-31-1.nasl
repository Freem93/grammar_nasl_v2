#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-31-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20647);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/25 16:34:55 $");

  script_cve_id("CVE-2004-1012", "CVE-2004-1013");
  script_xref(name:"USN", value:"31-1");

  script_name(english:"Ubuntu 4.10 : cyrus21-imapd vulnerabilities (USN-31-1)");
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
"Stefan Esser discovered several buffer overflows in the Cyrus IMAP
server. Due to insufficient checking within the argument parser of the
'partial' and 'fetch' commands, an argument like 'body[p' was detected
as 'body.peek'. This could cause a buffer overflow which could be
exploited to execute arbitrary attacker-supplied code.

This update also fixes an exploitable buffer overflow that could be
triggered in situations when memory allocation fails (i. e. when no
free memory is available any more).

Both vulnerabilities can lead to privilege escalation to root.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cyrus21-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cyrus21-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cyrus21-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cyrus21-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cyrus21-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cyrus21-imapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cyrus21-murder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cyrus21-pop3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcyrus-imap-perl21");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2004-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"cyrus21-admin", pkgver:"2.1.16-6ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"cyrus21-clients", pkgver:"2.1.16-6ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"cyrus21-common", pkgver:"2.1.16-6ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"cyrus21-dev", pkgver:"2.1.16-6ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"cyrus21-doc", pkgver:"2.1.16-6ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"cyrus21-imapd", pkgver:"2.1.16-6ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"cyrus21-murder", pkgver:"2.1.16-6ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"cyrus21-pop3d", pkgver:"2.1.16-6ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libcyrus-imap-perl21", pkgver:"2.1.16-6ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cyrus21-admin / cyrus21-clients / cyrus21-common / cyrus21-dev / etc");
}
