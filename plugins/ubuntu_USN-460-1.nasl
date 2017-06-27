#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-460-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28059);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/27 14:29:17 $");

  script_cve_id("CVE-2007-2444", "CVE-2007-2446", "CVE-2007-2447");
  script_osvdb_id(34698, 34699, 34700, 34731, 34732, 34733);
  script_xref(name:"USN", value:"460-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 : samba vulnerabilities (USN-460-1)");
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
"Paul Griffith and Andrew Hogue discovered that Samba did not fully
drop root privileges while translating SIDs. A remote authenticated
user could issue SMB operations during a small window of opportunity
and gain root privileges. (CVE-2007-2444)

Brian Schafer discovered that Samba did not handle NDR parsing
correctly. A remote attacker could send specially crafted MS-RPC
requests that could overwrite heap memory and execute arbitrary code.
(CVE-2007-2446)

It was discovered that Samba did not correctly escape input parameters
for external scripts defined in smb.conf. Remote authenticated users
could send specially crafted MS-RPC requests and execute arbitrary
shell commands. (CVE-2007-2447).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba "username map script" Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-smbpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsmbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:smbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:smbfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:winbind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/14");
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

if (ubuntu_check(osver:"6.06", pkgname:"libpam-smbpass", pkgver:"3.0.22-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libsmbclient", pkgver:"3.0.22-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libsmbclient-dev", pkgver:"3.0.22-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-samba", pkgver:"3.0.22-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"samba", pkgver:"3.0.22-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"samba-common", pkgver:"3.0.22-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"samba-dbg", pkgver:"3.0.22-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"samba-doc", pkgver:"3.0.22-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"samba-doc-pdf", pkgver:"3.0.22-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"smbclient", pkgver:"3.0.22-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"smbfs", pkgver:"3.0.22-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"swat", pkgver:"3.0.22-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"winbind", pkgver:"3.0.22-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libpam-smbpass", pkgver:"3.0.22-1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libsmbclient", pkgver:"3.0.22-1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libsmbclient-dev", pkgver:"3.0.22-1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"python2.4-samba", pkgver:"3.0.22-1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"samba", pkgver:"3.0.22-1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"samba-common", pkgver:"3.0.22-1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"samba-dbg", pkgver:"3.0.22-1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"samba-doc", pkgver:"3.0.22-1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"samba-doc-pdf", pkgver:"3.0.22-1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"smbclient", pkgver:"3.0.22-1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"smbfs", pkgver:"3.0.22-1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"swat", pkgver:"3.0.22-1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"winbind", pkgver:"3.0.22-1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libpam-smbpass", pkgver:"3.0.24-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libsmbclient", pkgver:"3.0.24-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libsmbclient-dev", pkgver:"3.0.24-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"python-samba", pkgver:"3.0.24-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"samba", pkgver:"3.0.24-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"samba-common", pkgver:"3.0.24-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"samba-dbg", pkgver:"3.0.24-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"samba-doc", pkgver:"3.0.24-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"samba-doc-pdf", pkgver:"3.0.24-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"smbclient", pkgver:"3.0.24-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"smbfs", pkgver:"3.0.24-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"swat", pkgver:"3.0.24-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"winbind", pkgver:"3.0.24-2ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpam-smbpass / libsmbclient / libsmbclient-dev / python-samba / etc");
}
