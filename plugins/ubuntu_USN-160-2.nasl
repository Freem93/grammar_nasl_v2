#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice FILES/USN-160-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20566);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/27 14:21:16 $");

  script_cve_id("CVE-2005-2088");
  script_osvdb_id(17738);
  script_xref(name:"USN", value:"160-2");

  script_name(english:"Ubuntu 4.10 / 5.04 : apache vulnerability (USN-160-2)");
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
"USN-160-1 fixed two vulnerabilities in the Apache 2 server. The old
Apache 1 server was also vulnerable to one of the vulnerabilities
(CAN-2005-2088). Please note that Apache 1 is not officially supported
in Ubuntu (it is in the 'universe' component of the archive).

For reference, this is the relevant part of the original advisory :

Watchfire discovered that Apache insufficiently verified the
'Transfer-Encoding' and 'Content-Length' headers when acting as an
HTTP proxy. By sending a specially crafted HTTP request, a remote
attacker who is authorized to use the proxy could exploit this to
bypass web application firewalls, poison the HTTP proxy cache, and
conduct cross-site scripting attacks against other proxy users.
(CAN-2005-2088).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache-ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache-mod-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/06");
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

if (ubuntu_check(osver:"4.10", pkgname:"apache", pkgver:"1.3.31-6ubuntu0.8")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache-common", pkgver:"1.3.31-6ubuntu0.8")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache-dbg", pkgver:"1.3.31-6ubuntu0.8")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache-dev", pkgver:"1.3.31-6ubuntu0.8")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache-doc", pkgver:"1.3.31-6ubuntu0.8")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache-perl", pkgver:"1.3.31-6ubuntu0.8")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache-ssl", pkgver:"1.3.31-6ubuntu0.8")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache-utils", pkgver:"1.3.31-6ubuntu0.8")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libapache-mod-perl", pkgver:"1.29.0.2.0-6ubuntu0.8")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache", pkgver:"1.3.33-4ubuntu1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache-common", pkgver:"1.3.33-4ubuntu1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache-dbg", pkgver:"1.3.33-4ubuntu1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache-dev", pkgver:"1.3.33-4ubuntu1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache-doc", pkgver:"1.3.33-4ubuntu1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache-perl", pkgver:"1.3.33-4ubuntu1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache-ssl", pkgver:"1.3.33-4ubuntu1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache-utils", pkgver:"1.3.33-4ubuntu1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libapache-mod-perl", pkgver:"1.29.0.3-4ubuntu1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache / apache-common / apache-dbg / apache-dev / apache-doc / etc");
}
