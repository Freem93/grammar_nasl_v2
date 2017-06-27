#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-870-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43108);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/27 14:45:43 $");

  script_cve_id("CVE-2009-2940");
  script_osvdb_id(59028);
  script_xref(name:"USN", value:"870-1");

  script_name(english:"Ubuntu 8.04 LTS / 8.10 : pygresql vulnerability (USN-870-1)");
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
"Steffen Joeris discovered that PyGreSQL 3.8 did not use PostgreSQL's
safe string and bytea functions in its own escaping functions. As a
result, applications written to use PyGreSQL's escaping functions are
vulnerable to SQL injections when processing certain multi-byte
character sequences. Because the safe functions require a database
connection, to maintain backwards compatibility, pg.escape_string()
and pg.escape_bytea() are still available, but applications will have
to be adjusted to use the new pyobj.escape_string() and
pyobj.escape_bytea() functions. For example, code containing :

import pg connection = pg.connect(...) escaped =
pg.escape_string(untrusted_input)

should be adjusted to use :

import pg connection = pg.connect(...) escaped =
connection.escape_string(untrusted_input).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected python-pygresql and / or python-pygresql-dbg
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-pygresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-pygresql-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(8\.04|8\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 8.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"python-pygresql", pkgver:"1:3.8.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python-pygresql-dbg", pkgver:"3.8.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"python-pygresql", pkgver:"1:3.8.1-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"python-pygresql-dbg", pkgver:"3.8.1-3ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-pygresql / python-pygresql-dbg");
}
