#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3158-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95949);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/03/31 21:35:24 $");

  script_cve_id("CVE-2016-2123", "CVE-2016-2125", "CVE-2016-2126");
  script_osvdb_id(149000, 149001, 149002);
  script_xref(name:"USN", value:"3158-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 16.04 LTS / 16.10 : samba vulnerabilities (USN-3158-1)");
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
"Frederic Besler and others discovered that the ndr_pull_dnsp_nam
function in Samba contained an integer overflow. An authenticated
attacker could use this to gain administrative privileges. This issue
only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS, and Ubuntu 16.10.
(CVE-2016-2123)

Simo Sorce discovered that that Samba clients always requested a
forwardable ticket when using Kerberos authentication. An attacker
could use this to impersonate an authenticated user or service.
(CVE-2016-2125)

Volker Lendecke discovered that Kerberos PAC validation implementation
in Samba contained multiple vulnerabilities. An authenticated attacker
could use this to cause a denial of service or gain administrative
privileges. This issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04
LTS, and Ubuntu 16.10. (CVE-2016-2126).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libsmbclient, samba and / or winbind packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:winbind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016-2017 Canonical, Inc. / NASL script (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|16\.04|16\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 16.04 / 16.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libsmbclient", pkgver:"2:3.6.25-0ubuntu0.12.04.5")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"samba", pkgver:"2:3.6.25-0ubuntu0.12.04.5")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libsmbclient", pkgver:"2:4.3.11+dfsg-0ubuntu0.14.04.4")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"samba", pkgver:"2:4.3.11+dfsg-0ubuntu0.14.04.4")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"winbind", pkgver:"2:4.3.11+dfsg-0ubuntu0.14.04.4")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libsmbclient", pkgver:"2:4.3.11+dfsg-0ubuntu0.16.04.3")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"samba", pkgver:"2:4.3.11+dfsg-0ubuntu0.16.04.3")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"winbind", pkgver:"2:4.3.11+dfsg-0ubuntu0.16.04.3")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"libsmbclient", pkgver:"2:4.4.5+dfsg-2ubuntu5.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"samba", pkgver:"2:4.4.5+dfsg-2ubuntu5.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"winbind", pkgver:"2:4.4.5+dfsg-2ubuntu5.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsmbclient / samba / winbind");
}
