#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-585-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31461);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:29:19 $");

  script_cve_id("CVE-2007-2052", "CVE-2007-4965");
  script_bugtraq_id(25696);
  script_osvdb_id(35247, 40142);
  script_xref(name:"USN", value:"585-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 / 7.10 : python2.4/2.5 vulnerabilities (USN-585-1)");
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
"Piotr Engelking discovered that strxfrm in Python was not correctly
calculating the size of the destination buffer. This could lead to
small information leaks, which might be used by attackers to gain
additional knowledge about the state of a running Python script.
(CVE-2007-2052)

A flaw was discovered in the Python imageop module. If a script using
the module could be tricked into processing a specially crafted set of
arguments, a remote attacker could execute arbitrary code, or cause
the application to crash. (CVE-2007-4965).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python2.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-gdbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.5-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.5-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.5-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.5-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/31");
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

if (ubuntu_check(osver:"6.06", pkgname:"idle-python2.4", pkgver:"2.4.3-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4", pkgver:"2.4.3-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-dbg", pkgver:"2.4.3-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-dev", pkgver:"2.4.3-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-doc", pkgver:"2.4.3-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-examples", pkgver:"2.4.3-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-gdbm", pkgver:"2.4.3-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-minimal", pkgver:"2.4.3-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-tk", pkgver:"2.4.3-0ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"idle-python2.4", pkgver:"2.4.4~c1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"idle-python2.5", pkgver:"2.5-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"python2.4", pkgver:"2.4.4~c1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"python2.4-dbg", pkgver:"2.4.4~c1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"python2.4-dev", pkgver:"2.4.4~c1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"python2.4-doc", pkgver:"2.4.4~c1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"python2.4-examples", pkgver:"2.4.4~c1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"python2.4-minimal", pkgver:"2.4.4~c1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"python2.5", pkgver:"2.5-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"python2.5-dbg", pkgver:"2.5-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"python2.5-dev", pkgver:"2.5-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"python2.5-doc", pkgver:"2.5-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"python2.5-examples", pkgver:"2.5-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"python2.5-minimal", pkgver:"2.5-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"idle-python2.4", pkgver:"2.4.4-2ubuntu7.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"idle-python2.5", pkgver:"2.5.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"python2.4", pkgver:"2.4.4-2ubuntu7.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"python2.4-dbg", pkgver:"2.4.4-2ubuntu7.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"python2.4-dev", pkgver:"2.4.4-2ubuntu7.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"python2.4-doc", pkgver:"2.4.4-2ubuntu7.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"python2.4-examples", pkgver:"2.4.4-2ubuntu7.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"python2.4-minimal", pkgver:"2.4.4-2ubuntu7.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"python2.5", pkgver:"2.5.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"python2.5-dbg", pkgver:"2.5.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"python2.5-dev", pkgver:"2.5.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"python2.5-doc", pkgver:"2.5.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"python2.5-examples", pkgver:"2.5.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"python2.5-minimal", pkgver:"2.5.1-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"idle-python2.4", pkgver:"2.4.4-6ubuntu4.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"idle-python2.5", pkgver:"2.5.1-5ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"python2.4", pkgver:"2.4.4-6ubuntu4.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"python2.4-dbg", pkgver:"2.4.4-6ubuntu4.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"python2.4-dev", pkgver:"2.4.4-6ubuntu4.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"python2.4-doc", pkgver:"2.4.4-6ubuntu4.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"python2.4-examples", pkgver:"2.4.4-6ubuntu4.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"python2.4-minimal", pkgver:"2.4.4-6ubuntu4.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"python2.5", pkgver:"2.5.1-5ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"python2.5-dbg", pkgver:"2.5.1-5ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"python2.5-dev", pkgver:"2.5.1-5ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"python2.5-doc", pkgver:"2.5.1-5ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"python2.5-examples", pkgver:"2.5.1-5ubuntu5.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"python2.5-minimal", pkgver:"2.5.1-5ubuntu5.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "idle-python2.4 / idle-python2.5 / python2.4 / python2.4-dbg / etc");
}
