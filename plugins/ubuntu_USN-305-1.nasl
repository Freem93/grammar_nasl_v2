#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-305-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27880);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:21:17 $");

  script_cve_id("CVE-2006-2754");
  script_osvdb_id(25659);
  script_xref(name:"USN", value:"305-1");

  script_name(english:"Ubuntu 5.04 / 5.10 / 6.06 LTS : openldap2, openldap2.2 vulnerability (USN-305-1)");
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
"When processing overly long host names in OpenLDAP's slurpd
replication server, a buffer overflow caused slurpd to crash.

If an attacker manages to inject a specially crafted host name into
slurpd, this might also be exploited to execute arbitrary code with
slurpd's privileges; however, since slurpd is usually set up to
replicate only trusted machines, this should not be exploitable in
normal cases.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ldap-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libldap-2.2-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libldap2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libldap2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libslapd2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:slapd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/19");
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

if (ubuntu_check(osver:"5.04", pkgname:"ldap-utils", pkgver:"2.1.30-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libldap2", pkgver:"2.1.30-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libldap2-dev", pkgver:"2.1.30-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libslapd2-dev", pkgver:"2.1.30-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"slapd", pkgver:"2.1.30-3ubuntu3.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"ldap-utils", pkgver:"2.2.26-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libldap-2.2-7", pkgver:"2.2.26-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"slapd", pkgver:"2.2.26-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ldap-utils", pkgver:"2.2.26-5ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libldap-2.2-7", pkgver:"2.2.26-5ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"slapd", pkgver:"2.2.26-5ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ldap-utils / libldap-2.2-7 / libldap2 / libldap2-dev / etc");
}
