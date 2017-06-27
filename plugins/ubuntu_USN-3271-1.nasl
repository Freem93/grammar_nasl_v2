#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3271-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99725);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/02 13:34:10 $");

  script_cve_id("CVE-2015-7995", "CVE-2016-1683", "CVE-2016-1684", "CVE-2016-1841", "CVE-2016-4738", "CVE-2017-5029");
  script_osvdb_id(126901, 138573, 139031, 139032, 144562, 151459);
  script_xref(name:"USN", value:"3271-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 16.04 LTS / 16.10 / 17.04 : libxslt vulnerabilities (USN-3271-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Holger Fuhrmannek discovered an integer overflow in the
xsltAddTextString() function in Libxslt. An attacker could use this to
craft a malicious document that, when opened, could cause a denial of
service (application crash) or possible execute arbitrary code.
(CVE-2017-5029)

Nicolas Gregoire discovered that Libxslt mishandled namespace nodes.
An attacker could use this to craft a malicious document that, when
opened, could cause a denial of service (application crash) or
possibly execute arbtrary code. This issue only affected Ubuntu 16.04
LTS, Ubuntu 14.04 LTS, and Ubuntu 12.04 LTS. (CVE-2016-1683)

Sebastian Apelt discovered that a use-after-error existed in the
xsltDocumentFunctionLoadDocument() function in Libxslt. An attacker
could use this to craft a malicious document that, when opened, could
cause a denial of service (application crash) or possibly execute
arbitrary code. This issue only affected Ubuntu 16.04 LTS, Ubuntu
14.04 LTS, and Ubuntu 12.04 LTS. (CVE-2016-1841)

It was discovered that a type confusion error existed in the
xsltStylePreCompute() function in Libxslt. An attacker could use this
to craft a malicious XML file that, when opened, caused a denial of
service (application crash). This issue only affected Ubuntu 14.04 LTS
and Ubuntu 12.04 LTS. (CVE-2015-7995)

Nicolas Gregoire discovered the Libxslt mishandled the 'i' and 'a'
format tokens for xsl:number data. An attacker could use this to craft
a malicious document that, when opened, could cause a denial of
service (application crash). This issue only affected Ubuntu 16.04
LTS, Ubuntu 14.04 LTS, and Ubuntu 12.04 LTS. (CVE-2016-1684)

It was discovered that the xsltFormatNumberConversion() function in
Libxslt did not properly handle empty decimal separators. An attacker
could use this to craft a malicious document that, when opened, could
cause a denial of service (application crash). This issue only
affected Ubuntu 16.10, Ubuntu 16.04 LTS, Ubuntu 14.04 LTS, and Ubuntu
12.04 LTS. (CVE-2016-4738).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxslt1.1 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxslt1.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2017 Canonical, Inc. / NASL script (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|16\.04|16\.10|17\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 16.04 / 16.10 / 17.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libxslt1.1", pkgver:"1.1.26-8ubuntu1.4")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libxslt1.1", pkgver:"1.1.28-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libxslt1.1", pkgver:"1.1.28-2.1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"libxslt1.1", pkgver:"1.1.29-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"libxslt1.1", pkgver:"1.1.29-2ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxslt1.1");
}
