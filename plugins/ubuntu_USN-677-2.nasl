#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-677-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(37546);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2008-2237", "CVE-2008-2238", "CVE-2008-4937");
  script_bugtraq_id(31962);
  script_xref(name:"USN", value:"677-2");

  script_name(english:"Ubuntu 8.04 LTS : openoffice.org-l10n update (USN-677-2)");
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
"USN-677-1 fixed vulnerabilities in OpenOffice.org. The changes
required that openoffice.org-l10n also be updated for the new version
in Ubuntu 8.04 LTS.

Multiple memory overflow flaws were discovered in OpenOffice.org's
handling of WMF and EMF files. If a user were tricked into opening a
specially crafted document, a remote attacker might be able to execute
arbitrary code with user privileges. (CVE-2008-2237, CVE-2008-2238)

Dmitry E. Oboukhov discovered that senddoc, as included in
OpenOffice.org, created temporary files in an insecure way.
Local users could exploit a race condition to create or
overwrite files with the privileges of the user invoking the
program. This issue only affected Ubuntu 8.04 LTS.
(CVE-2008-4937).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(59, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-help-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-help-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-help-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-help-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-help-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-help-en-gb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-help-en-us");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-help-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-help-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-help-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-help-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-help-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-help-hi-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-help-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-help-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-help-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-help-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-help-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-help-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-help-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-help-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-help-pt-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-help-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-help-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-help-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-help-zh-cn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-help-zh-tw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-as-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-be-by");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-en-gb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-en-za");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-eo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-gu-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-hi-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-ku");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-lo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-ml-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-mr-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-ne");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-ns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-or-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-pa-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-pt-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-rw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-sw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-ta-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-te-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-tg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-ti-er");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-ur-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-ve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-zh-cn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-zh-tw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-zu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(8\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-help-br", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-help-cs", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-help-da", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-help-de", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-help-dz", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-help-en-gb", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-help-en-us", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-help-es", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-help-et", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-help-eu", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-help-fr", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-help-gl", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-help-hi-in", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-help-hu", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-help-it", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-help-ja", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-help-km", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-help-ko", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-help-nl", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-help-pl", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-help-pt", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-help-pt-br", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-help-ru", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-help-sl", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-help-sv", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-help-zh-cn", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-help-zh-tw", pkgver:"2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-af", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-ar", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-as-in", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-be-by", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-bg", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-bn", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-br", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-bs", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-ca", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-common", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-cs", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-cy", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-da", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-de", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-dz", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-el", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-en-gb", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-en-za", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-eo", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-es", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-et", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-eu", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-fa", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-fi", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-fr", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-ga", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-gl", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-gu-in", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-he", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-hi-in", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-hr", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-hu", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-it", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-ja", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-ka", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-km", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-kn", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-ko", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-ku", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-lo", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-lt", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-lv", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-mk", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-ml-in", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-mr-in", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-nb", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-ne", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-nl", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-nn", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-nr", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-ns", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-or-in", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-pa-in", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-pl", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-pt", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-pt-br", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-ro", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-ru", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-rw", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-sk", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-sl", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-sr", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-ss", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-st", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-sv", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-sw", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-ta-in", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-te-in", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-tg", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-th", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-ti-er", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-tn", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-tr", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-ts", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-uk", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-ur-in", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-uz", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-ve", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-vi", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-xh", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-zh-cn", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-zh-tw", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-zu", pkgver:"1:2.4.1-1ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openoffice.org-help-br / openoffice.org-help-cs / etc");
}
