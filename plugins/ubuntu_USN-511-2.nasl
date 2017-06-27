#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-511-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28116);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/27 14:29:18 $");

  script_cve_id("CVE-2007-4743");
  script_bugtraq_id(25534);
  script_osvdb_id(37332);
  script_xref(name:"USN", value:"511-2");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 : krb5, librpcsecgss vulnerability (USN-511-2)");
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
"USN-511-1 fixed vulnerabilities in krb5 and librpcsecgss. The fixes
were incomplete, and only reduced the scope of the vulnerability,
without fully solving it. This update fixes the problem.

It was discovered that the libraries handling RPCSEC_GSS did not
correctly validate the size of certain packet structures. An
unauthenticated remote user could send a specially crafted request and
execute arbitrary code with root privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-admin-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-ftpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-kdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-rsh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-telnetd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librpcsecgss-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librpcsecgss1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librpcsecgss2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librpcsecgss3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2007-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|6\.10|7\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 6.10 / 7.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"krb5-admin-server", pkgver:"1.4.3-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krb5-clients", pkgver:"1.4.3-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krb5-doc", pkgver:"1.4.3-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krb5-ftpd", pkgver:"1.4.3-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krb5-kdc", pkgver:"1.4.3-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krb5-rsh-server", pkgver:"1.4.3-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krb5-telnetd", pkgver:"1.4.3-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krb5-user", pkgver:"1.4.3-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libkadm55", pkgver:"1.4.3-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libkrb5-dev", pkgver:"1.4.3-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libkrb53", pkgver:"1.4.3-5ubuntu0.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"librpcsecgss-dev", pkgver:"0.7-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"librpcsecgss1", pkgver:"0.7-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"krb5-admin-server", pkgver:"1.4.3-9ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"krb5-clients", pkgver:"1.4.3-9ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"krb5-doc", pkgver:"1.4.3-9ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"krb5-ftpd", pkgver:"1.4.3-9ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"krb5-kdc", pkgver:"1.4.3-9ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"krb5-rsh-server", pkgver:"1.4.3-9ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"krb5-telnetd", pkgver:"1.4.3-9ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"krb5-user", pkgver:"1.4.3-9ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libkadm55", pkgver:"1.4.3-9ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libkrb5-dbg", pkgver:"1.4.3-9ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libkrb5-dev", pkgver:"1.4.3-9ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libkrb53", pkgver:"1.4.3-9ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"librpcsecgss-dev", pkgver:"0.13-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"librpcsecgss2", pkgver:"0.13-2ubuntu0.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"krb5-admin-server", pkgver:"1.4.4-5ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"krb5-clients", pkgver:"1.4.4-5ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"krb5-doc", pkgver:"1.4.4-5ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"krb5-ftpd", pkgver:"1.4.4-5ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"krb5-kdc", pkgver:"1.4.4-5ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"krb5-rsh-server", pkgver:"1.4.4-5ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"krb5-telnetd", pkgver:"1.4.4-5ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"krb5-user", pkgver:"1.4.4-5ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libkadm55", pkgver:"1.4.4-5ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libkrb5-dbg", pkgver:"1.4.4-5ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libkrb5-dev", pkgver:"1.4.4-5ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libkrb53", pkgver:"1.4.4-5ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"librpcsecgss-dev", pkgver:"0.14-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"librpcsecgss3", pkgver:"0.14-2ubuntu1.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-admin-server / krb5-clients / krb5-doc / krb5-ftpd / krb5-kdc / etc");
}
