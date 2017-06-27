#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-201-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20617);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/26 16:22:49 $");

  script_cve_id("CVE-2005-2724", "CVE-2005-2769", "CVE-2005-2820");
  script_osvdb_id(18948, 19047, 19262);
  script_xref(name:"USN", value:"201-1");

  script_name(english:"Ubuntu 4.10 / 5.04 : courier vulnerabilities (USN-201-1)");
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
"Several Cross Site Scripting vulnerabilities were discovered in
SqWebmail. A remote attacker could exploit this to execute arbitrary
JavaScript or other active HTML embeddable content in the web browser
of an SqWebmail user by sending specially crafted emails to him.

Please note that the 'sqwebmail' package is not officially supported
by Ubuntu (it is in the 'universe' section of the archive).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:courier-authdaemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:courier-authmysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:courier-authpostgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:courier-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:courier-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:courier-faxmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:courier-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:courier-imap-ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:courier-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:courier-maildrop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:courier-mlm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:courier-mta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:courier-mta-ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:courier-pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:courier-pop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:courier-pop-ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:courier-ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:courier-webadmin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sqwebmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2005-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4\.10|5\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10 / 5.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"courier-authdaemon", pkgver:"0.45.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"courier-authmysql", pkgver:"0.45.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"courier-authpostgresql", pkgver:"0.45.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"courier-base", pkgver:"0.45.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"courier-doc", pkgver:"0.45.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"courier-faxmail", pkgver:"0.45.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"courier-imap", pkgver:"3.0.5-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"courier-imap-ssl", pkgver:"3.0.5-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"courier-ldap", pkgver:"0.45.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"courier-maildrop", pkgver:"0.45.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"courier-mlm", pkgver:"0.45.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"courier-mta", pkgver:"0.45.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"courier-mta-ssl", pkgver:"0.45.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"courier-pcp", pkgver:"0.45.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"courier-pop", pkgver:"0.45.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"courier-pop-ssl", pkgver:"0.45.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"courier-ssl", pkgver:"0.45.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"courier-webadmin", pkgver:"0.45.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"sqwebmail", pkgver:"0.45.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"courier-authdaemon", pkgver:"0.47-3ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"courier-authmysql", pkgver:"0.47-3ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"courier-authpostgresql", pkgver:"0.47-3ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"courier-base", pkgver:"0.47-3ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"courier-doc", pkgver:"0.47-3ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"courier-faxmail", pkgver:"0.47-3ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"courier-imap", pkgver:"3.0.8-3ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"courier-imap-ssl", pkgver:"3.0.8-3ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"courier-ldap", pkgver:"0.47-3ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"courier-maildrop", pkgver:"0.47-3ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"courier-mlm", pkgver:"0.47-3ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"courier-mta", pkgver:"0.47-3ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"courier-mta-ssl", pkgver:"0.47-3ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"courier-pcp", pkgver:"0.47-3ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"courier-pop", pkgver:"0.47-3ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"courier-pop-ssl", pkgver:"0.47-3ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"courier-ssl", pkgver:"0.47-3ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"courier-webadmin", pkgver:"0.47-3ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"sqwebmail", pkgver:"0.47-3ubuntu1.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "courier-authdaemon / courier-authmysql / courier-authpostgresql / etc");
}
