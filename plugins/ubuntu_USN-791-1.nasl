#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-791-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39516);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2007-3215", "CVE-2008-4796", "CVE-2008-4810", "CVE-2008-4811", "CVE-2008-5153", "CVE-2008-5432", "CVE-2008-5619", "CVE-2008-6124", "CVE-2009-0499", "CVE-2009-0500", "CVE-2009-0501", "CVE-2009-0502", "CVE-2009-1171", "CVE-2009-1669");
  script_bugtraq_id(31862, 31887, 32402, 32799, 33610, 33612, 34278, 34918);
  script_xref(name:"USN", value:"791-1");

  script_name(english:"Ubuntu 8.04 LTS / 8.10 : moodle vulnerabilities (USN-791-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Thor Larholm discovered that PHPMailer, as used by Moodle, did not
correctly escape email addresses. A local attacker with direct access
to the Moodle database could exploit this to execute arbitrary
commands as the web server user. (CVE-2007-3215)

Nigel McNie discovered that fetching https URLs did not correctly
escape shell meta-characters. An authenticated remote attacker could
execute arbitrary commands as the web server user, if curl was
installed and configured. (CVE-2008-4796, MSA-09-0003)

It was discovered that Smarty (also included in Moodle), did not
correctly filter certain inputs. An authenticated remote attacker
could exploit this to execute arbitrary PHP commands as the web server
user. (CVE-2008-4810, CVE-2008-4811, CVE-2009-1669)

It was discovered that the unused SpellChecker extension in Moodle did
not correctly handle temporary files. If the tool had been locally
modified, it could be made to overwrite arbitrary local files via
symlinks. (CVE-2008-5153)

Mike Churchward discovered that Moodle did not correctly filter Wiki
page titles in certain areas. An authenticated remote attacker could
exploit this to cause cross-site scripting (XSS), which could be used
to modify or steal confidential data of other users within the same
web domain. (CVE-2008-5432, MSA-08-0022)

It was discovered that the HTML sanitizer, 'Login as' feature, and
logging in Moodle did not correctly handle certain inputs. An
authenticated remote attacker could exploit this to generate XSS,
which could be used to modify or steal confidential data of other
users within the same web domain. (CVE-2008-5619, CVE-2009-0500,
CVE-2009-0502, MSA-08-0026, MSA-09-0004, MSA-09-0007)

It was discovered that the HotPot module in Moodle did not correctly
filter SQL inputs. An authenticated remote attacker could execute
arbitrary SQL commands as the moodle database user, leading to a loss
of privacy or denial of service. (CVE-2008-6124, MSA-08-0010)

Kevin Madura discovered that the forum actions and messaging settings
in Moodle were not protected from cross-site request forgery (CSRF).
If an authenticated user were tricked into visiting a malicious
website while logged into Moodle, a remote attacker could change the
user's configurations or forum content. (CVE-2009-0499, MSA-09-0008,
MSA-08-0023)

Daniel Cabezas discovered that Moodle would leak usernames from the
Calendar Export tool. A remote attacker could gather a list of users,
leading to a loss of privacy. (CVE-2009-0501, MSA-09-0006)

Christian Eibl discovered that the TeX filter in Moodle allowed any
function to be used. An authenticated remote attacker could post a
specially crafted TeX formula to execute arbitrary TeX functions,
potentially reading any file accessible to the web server user,
leading to a loss of privacy. (CVE-2009-1171, MSA-09-0009)

Johannes Kuhn discovered that Moodle did not correctly validate user
permissions when attempting to switch user accounts. An authenticated
remote attacker could switch to any other Moodle user, leading to a
loss of privacy. (MSA-08-0003)

Hanno Boeck discovered that unconfigured Moodle instances contained
XSS vulnerabilities. An unauthenticated remote attacker could exploit
this to modify or steal confidential data of other users within the
same web domain. (MSA-08-0004)

Debbie McDonald, Mauno Korpelainen, Howard Miller, and Juan Segarra
Montesinos discovered that when users were deleted from Moodle, their
profiles and avatars were still visible. An authenticated remote
attacker could exploit this to store information in profiles even
after they were removed, leading to spam traffic. (MSA-08-0015,
MSA-09-0001, MSA-09-0002)

Lars Vogdt discovered that Moodle did not correctly filter certain
inputs. An authenticated remote attacker could exploit this to
generate XSS from which they could modify or steal confidential data
of other users within the same web domain. (MSA-08-0021)

It was discovered that Moodle did not correctly filter inputs for
group creation, mnet, essay question, HOST param, wiki param, and
others. An authenticated remote attacker could exploit this to
generate XSS from which they could modify or steal confidential data
of other users within the same web domain. (MDL-9288, MDL-11759,
MDL-12079, MDL-12793, MDL-14806)

It was discovered that Moodle did not correctly filter SQL inputs when
performing a restore. An attacker authenticated as a Moodle
administrator could execute arbitrary SQL commands as the moodle
database user, leading to a loss of privacy or denial of service.
(MDL-11857).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected moodle package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Roundcube 0.2beta RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 59, 79, 89, 94, 264, 352);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:moodle");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/25");
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

if (ubuntu_check(osver:"8.04", pkgname:"moodle", pkgver:"1.8.2-1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"moodle", pkgver:"1.8.2-1.2ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "moodle");
}
