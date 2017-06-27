#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1197-4. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56139);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/26 16:14:09 $");

  script_xref(name:"USN", value:"1197-4");

  script_name(english:"Ubuntu 10.04 LTS / 10.10 / 11.04 : nss vulnerability (USN-1197-4)");
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
"USN-1197-1 and USN-1197-3 addressed an issue in Firefox and Xulrunner
pertaining to the Dutch Certificate Authority DigiNotar mis-issuing
fraudulent certificates. This update provides the corresponding update
for the Network Security Service libraries (NSS).

USN-1197-1

It was discovered that Dutch Certificate Authority
DigiNotar, had mis-issued multiple fraudulent certificates.
These certificates could allow an attacker to perform a 'man
in the middle' (MITM) attack which would make the user
believe their connection is secure, but is actually being
monitored.

For the protection of its users, Mozilla has removed the
DigiNotar certificate. Sites using certificates issued by
DigiNotar will need to seek another certificate vendor.

We are currently aware of a regression that blocks one of
two Staat der Nederlanden root certificates which are
believed to still be secure. This regression is being
tracked at https://launchpad.net/bugs/838322.

USN-1197-3

USN-1197-1 partially addressed an issue with Dutch
Certificate Authority DigiNotar mis-issuing fraudulent
certificates. This update actively distrusts the DigiNotar
root certificate as well as several intermediary
certificates. Also included in this list of distrusted
certificates are the 'PKIOverheid' (PKIGovernment)
intermediates under DigiNotar's control that did not chain
to DigiNotar's root and were not previously blocked.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libnss3 and / or libnss3-1d packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnss3-1d");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2016 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04|10\.10|11\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 10.10 / 11.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"libnss3-1d", pkgver:"3.12.9+ckbi-1.82-0ubuntu0.10.04.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libnss3-1d", pkgver:"3.12.9+ckbi-1.82-0ubuntu0.10.10.3")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"libnss3", pkgver:"3.12.9+ckbi-1.82-0ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libnss3 / libnss3-1d");
}
