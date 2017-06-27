#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-173-4. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20583);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:21:16 $");

  script_cve_id("CVE-2005-2491");
  script_bugtraq_id(14620);
  script_xref(name:"USN", value:"173-4");

  script_name(english:"Ubuntu 4.10 / 5.04 : python2.1, python2.2, python2.3, gnumeric vulnerabilities (USN-173-4)");
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
"USN-173-1 fixed a buffer overflow vulnerability in the PCRE library.
However, it was found that the various python packages and gnumeric
contain static copies of the library code, so these packages need to
be updated as well.

In gnumeric this bug could be exploited to execute arbitrary code with
the privileges of the user if the user was tricked into opening a
specially crafted spreadsheet document.

In python, the impact depends on the particular application that uses
python's 're' (regular expression) module. In python server
applications that process unchecked arbitrary regular expressions with
the 're' module, this could potentially be exploited to remotely
execute arbitrary code with the privileges of the server.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnumeric");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnumeric-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnumeric-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnumeric-plugins-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python2.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python2.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python2.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.1-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.1-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.1-gdbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.1-mpz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.1-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.1-xmlbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.2-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.2-gdbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.2-mpz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.2-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.2-xmlbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.3-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.3-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.3-gdbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.3-mpz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.3-tk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/31");
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
if (! ereg(pattern:"^(4\.10|5\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10 / 5.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"gnumeric", pkgver:"1.2.13-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"gnumeric-common", pkgver:"1.2.13-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"gnumeric-doc", pkgver:"1.2.13-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"gnumeric-plugins-extra", pkgver:"1.2.13-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"idle-python2.1", pkgver:"2.1.3-24.ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"idle-python2.2", pkgver:"2.2.3-10.ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"idle-python2.3", pkgver:"2.3.4-2.ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"python2.1", pkgver:"2.1.3-24.ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"python2.1-dev", pkgver:"2.1.3-24.ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"python2.1-doc", pkgver:"2.1.3-24.ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"python2.1-examples", pkgver:"2.1.3-24.ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"python2.1-gdbm", pkgver:"2.1.3-24.ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"python2.1-mpz", pkgver:"2.1.3-24.ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"python2.1-tk", pkgver:"2.1.3-24.ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"python2.1-xmlbase", pkgver:"2.1.3-24.ubuntu0.1")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"python2.2", pkgver:"2.2.3-10.ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"python2.2-dev", pkgver:"2.2.3-10.ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"python2.2-doc", pkgver:"2.2.3-10.ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"python2.2-examples", pkgver:"2.2.3-10.ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"python2.2-gdbm", pkgver:"2.2.3-10.ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"python2.2-mpz", pkgver:"2.2.3-10.ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"python2.2-tk", pkgver:"2.2.3-10.ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"python2.2-xmlbase", pkgver:"2.2.3-10.ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"python2.3", pkgver:"2.3.4-2.ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"python2.3-dev", pkgver:"2.3.4-2.ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"python2.3-doc", pkgver:"2.3.4-2.ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"python2.3-examples", pkgver:"2.3.4-2.ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"python2.3-gdbm", pkgver:"2.3.4-2.ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"python2.3-mpz", pkgver:"2.3.4-2.ubuntu0.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"python2.3-tk", pkgver:"2.3.4-2.ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gnumeric", pkgver:"1.4.2-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gnumeric-common", pkgver:"1.4.2-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gnumeric-doc", pkgver:"1.4.2-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"gnumeric-plugins-extra", pkgver:"1.4.2-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"idle-python2.2", pkgver:"2.2.3dfsg-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"idle-python2.3", pkgver:"2.3.5-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.2", pkgver:"2.2.3dfsg-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.2-dev", pkgver:"2.2.3dfsg-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.2-doc", pkgver:"2.2.3dfsg-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.2-examples", pkgver:"2.2.3dfsg-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.2-gdbm", pkgver:"2.2.3dfsg-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.2-mpz", pkgver:"2.2.3dfsg-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.2-tk", pkgver:"2.2.3dfsg-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.2-xmlbase", pkgver:"2.2.3dfsg-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.3", pkgver:"2.3.5-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.3-dev", pkgver:"2.3.5-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.3-doc", pkgver:"2.3.5-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.3-examples", pkgver:"2.3.5-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.3-gdbm", pkgver:"2.3.5-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.3-mpz", pkgver:"2.3.5-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.3-tk", pkgver:"2.3.5-2ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnumeric / gnumeric-common / gnumeric-doc / gnumeric-plugins-extra / etc");
}
