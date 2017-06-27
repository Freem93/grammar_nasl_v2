#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-50-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20668);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/01 21:07:51 $");

  script_cve_id("CVE-2004-1125", "CVE-2004-1267", "CVE-2004-1268", "CVE-2004-1269", "CVE-2004-1270", "CVE-2004-2467");
  script_xref(name:"USN", value:"50-1");

  script_name(english:"Ubuntu 4.10 : cupsys vulnerabilities (USN-50-1)");
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
"CAN-2004-1125 :

The recent USN-48-1 fixed a buffer overflow in xpdf. Since CUPS
contains xpdf code to convert incoming PDF files to the PostScript
format, this vulnerability applies to cups as well.

In this case it could even lead to privilege escalation: if
an attacker submitted a malicious PDF file for printing, he
could be able to execute arbitrary commands with the
privileges of the CUPS server.

Please note that the Ubuntu version of CUPS runs as a
minimally privileged user 'cupsys' by default, so there is
no possibility of root privilege escalation. The privileges
of the 'cupsys' user are confined to modifying printer
configurations, altering print jobs, and controlling
printers.

CAN-2004-1267 :

Ariel Berkman discovered a buffer overflow in the ParseCommand()
function of the HPGL input driver. If an attacker printed a malicious
HPGL file, they could exploit this to execute arbitrary commands with
the privileges of the CUPS server.

CAN-2004-1268, CAN-2004-1269, CAN-2004-1270 :

Bartlomiej Sieka discovered three flaws in lppasswd. These allowed
users to corrupt the new password file by filling up the disk, sending
certain signals, or closing the standard output and/or error streams.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys-bsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cupsys-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsimage2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsimage2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsys2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcupsys2-gnutls10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/23");
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

if (ubuntu_check(osver:"4.10", pkgname:"cupsys", pkgver:"1.1.20final+cvs20040330-4ubuntu16.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"cupsys-bsd", pkgver:"1.1.20final+cvs20040330-4ubuntu16.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"cupsys-client", pkgver:"1.1.20final+cvs20040330-4ubuntu16.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libcupsimage2", pkgver:"1.1.20final+cvs20040330-4ubuntu16.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libcupsimage2-dev", pkgver:"1.1.20final+cvs20040330-4ubuntu16.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libcupsys2-dev", pkgver:"1.1.20final+cvs20040330-4ubuntu16.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libcupsys2-gnutls10", pkgver:"1.1.20final+cvs20040330-4ubuntu16.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cupsys / cupsys-bsd / cupsys-client / libcupsimage2 / etc");
}
