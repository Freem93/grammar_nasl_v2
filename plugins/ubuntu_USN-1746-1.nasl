#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1746-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64890);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/25 16:27:05 $");

  script_cve_id("CVE-2013-0271", "CVE-2013-0272", "CVE-2013-0273", "CVE-2013-0274");
  script_bugtraq_id(57951, 57952, 57954);
  script_osvdb_id(90231, 90232, 90233, 90234);
  script_xref(name:"USN", value:"1746-1");

  script_name(english:"Ubuntu 10.04 LTS / 11.10 / 12.04 LTS / 12.10 : pidgin vulnerabilities (USN-1746-1)");
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
"Chris Wysopal discovered that Pidgin incorrectly handled file
transfers in the MXit protocol handler. A remote attacker could use
this issue to create or overwrite arbitrary files. This issue only
affected Ubuntu 11.10, Ubuntu 12.04 LTS and Ubuntu 12.10.
(CVE-2013-0271)

It was discovered that Pidgin incorrectly handled long HTTP headers in
the MXit protocol handler. A malicious remote server could use this
issue to execute arbitrary code. (CVE-2013-0272)

It was discovered that Pidgin incorrectly handled long user IDs in the
Sametime protocol handler. A malicious remote server could use this
issue to cause Pidgin to crash, resulting in a denial of service.
(CVE-2013-0273)

It was discovered that Pidgin incorrectly handled long strings when
processing UPnP responses. A remote attacker could use this issue to
cause Pidgin to crash, resulting in a denial of service.
(CVE-2013-0274).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libpurple0 and / or pidgin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpurple0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2013-2016 Canonical, Inc. / NASL script (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04|11\.10|12\.04|12\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 11.10 / 12.04 / 12.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"libpurple0", pkgver:"1:2.6.6-1ubuntu4.6")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"pidgin", pkgver:"1:2.6.6-1ubuntu4.6")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"libpurple0", pkgver:"1:2.10.0-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"pidgin", pkgver:"1:2.10.0-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libpurple0", pkgver:"1:2.10.3-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"pidgin", pkgver:"1:2.10.3-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"libpurple0", pkgver:"1:2.10.6-0ubuntu2.2")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"pidgin", pkgver:"1:2.10.6-0ubuntu2.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpurple0 / pidgin");
}
