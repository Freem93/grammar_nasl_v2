#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-96-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20722);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/25 16:34:56 $");

  script_cve_id("CVE-2005-0709", "CVE-2005-0710", "CVE-2005-0711");
  script_xref(name:"USN", value:"96-1");

  script_name(english:"Ubuntu 4.10 : mysql-dfsg vulnerabilities (USN-96-1)");
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
"Stefano Di Paola discovered three privilege escalation flaws in the
MySQL server :

  - If an authenticated user had INSERT privileges on the
    'mysql' administrative database, the CREATE FUNCTION
    command allowed that user to use libc functions to
    execute arbitrary code with the privileges of the
    database server (user 'mysql'). (CAN-2005-0709)

  - If an authenticated user had INSERT privileges on the
    'mysql' administrative database, it was possible to load
    a library located in an arbitrary directory by using
    INSERT INTO mysql.func instead of CREATE FUNCTION. This
    allowed the user to execute arbitrary code with the
    privileges of the database server (user 'mysql').
    (CAN-2005-0710)

  - Temporary files belonging to tables created with CREATE
    TEMPORARY TABLE were handled in an insecure way. This
    allowed any local computer user to overwrite arbitrary
    files with the privileges of the database server.
    (CAN-2005-0711)

Matt Brubeck discovered that the directory /usr/share/mysql/ was owned
and writable by the database server user 'mysql'. This directory
contains scripts which are usually run by root. This allowed a local
attacker who already has mysql privileges to gain full root access by
modifying a script and tricking root into executing it.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmysqlclient12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
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
if (! ereg(pattern:"^(4\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"libmysqlclient-dev", pkgver:"4.0.20-2ubuntu1.4")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libmysqlclient12", pkgver:"4.0.20-2ubuntu1.4")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mysql-client", pkgver:"4.0.20-2ubuntu1.4")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mysql-common", pkgver:"4.0.20-2ubuntu1.4")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"mysql-server", pkgver:"4.0.20-2ubuntu1.4")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmysqlclient-dev / libmysqlclient12 / mysql-client / mysql-common / etc");
}
