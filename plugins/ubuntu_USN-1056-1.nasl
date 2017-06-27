#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1056-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51858);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/27 14:13:23 $");

  script_cve_id("CVE-2010-2935", "CVE-2010-2936", "CVE-2010-3450", "CVE-2010-3451", "CVE-2010-3452", "CVE-2010-3453", "CVE-2010-3454", "CVE-2010-3689", "CVE-2010-4253", "CVE-2010-4643");
  script_bugtraq_id(42202, 46031);
  script_xref(name:"USN", value:"1056-1");

  script_name(english:"Ubuntu 8.04 LTS / 9.10 / 10.04 LTS / 10.10 : openoffice.org vulnerabilities (USN-1056-1)");
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
"Charlie Miller discovered several heap overflows in PPT processing. If
a user or automated system were tricked into opening a specially
crafted PPT document, a remote attacker could execute arbitrary code
with user privileges. Ubuntu 10.10 was not affected. (CVE-2010-2935,
CVE-2010-2936)

Marc Schoenefeld discovered that directory traversal was not correctly
handled in XSLT, OXT, JAR, or ZIP files. If a user or automated system
were tricked into opening a specially crafted document, a remote
attacker overwrite arbitrary files, possibly leading to arbitrary code
execution with user privileges. (CVE-2010-3450)

Dan Rosenberg discovered multiple heap overflows in RTF and DOC
processing. If a user or automated system were tricked into opening a
specially crafted RTF or DOC document, a remote attacker could execute
arbitrary code with user privileges. (CVE-2010-3451, CVE-2010-3452,
CVE-2010-3453, CVE-2010-3454)

Dmitri Gribenko discovered that OpenOffice.org did not correctly
handle LD_LIBRARY_PATH in various tools. If a local attacker tricked a
user or automated system into using OpenOffice.org from an
attacker-controlled directory, they could execute arbitrary code with
user privileges. (CVE-2010-3689)

Marc Schoenefeld discovered that OpenOffice.org did not correctly
process PNG images. If a user or automated system were tricked into
opening a specially crafted document, a remote attacker could execute
arbitrary code with user privileges. (CVE-2010-4253)

It was discovered that OpenOffice.org did not correctly process TGA
images. If a user or automated system were tricked into opening a
specially crafted document, a remote attacker could execute arbitrary
code with user privileges. (CVE-2010-4643).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:broffice.org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cli-uno-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmythes-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libuno-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libuno-cli-basetypes1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libuno-cli-cppuhelper1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libuno-cli-oootypes1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libuno-cli-ure1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libuno-cli-uretypes1.0-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-openoffice.org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-base-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-dev-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-dtd-officedocument1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-emailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-filter-binfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-filter-mobiledev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-gcj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-java-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-za");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-mysql-connector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-ogltrans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-pdfimport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-presentation-minimizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-presenter-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-qa-api-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-qa-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-report-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-report-builder-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-sdbc-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-style-andromeda");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-style-crystal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-style-galaxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-style-hicontrast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-style-human");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-style-industrial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-style-oxygen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-style-tango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-wiki-publisher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-uno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ttf-opensymbol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uno-libs3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uno-libs3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ure-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/03");
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
if (! ereg(pattern:"^(8\.04|9\.10|10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 9.10 / 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"broffice.org", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmythes-dev", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libuno-cil", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mozilla-openoffice.org", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-base", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-base-core", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-calc", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-common", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-core", pkgver:"1:2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-dev", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-dev-doc", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-draw", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-dtd-officedocument1.0", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-evolution", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-filter-binfilter", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-filter-mobiledev", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-gcj", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-gnome", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-gtk", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-headless", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-impress", pkgver:"1:2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-java-common", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-kde", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-in", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-za", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-math", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-officebean", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-ogltrans", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-presentation-minimizer", pkgver:"1.0+OOo2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-qa-api-tests", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-qa-tools", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-report-builder", pkgver:"1.0.2+OOo2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-sdbc-postgresql", pkgver:"0.7.5+OOo2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-style-andromeda", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-style-crystal", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-style-hicontrast", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-style-human", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-style-industrial", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-style-tango", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-writer", pkgver:"1:2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python-uno", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ttf-opensymbol", pkgver:"2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ure", pkgver:"1.4+OOo2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ure-dbg", pkgver:"1.4+OOo2.4.1-1ubuntu2.5")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"broffice.org", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"cli-uno-bridge", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libmythes-dev", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libuno-cli-basetypes1.0-cil", pkgver:"1.0.14.0+OOo3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libuno-cli-cppuhelper1.0-cil", pkgver:"1.0.17.0+OOo3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libuno-cli-oootypes1.0-cil", pkgver:"1.0.3.0+OOo3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libuno-cli-ure1.0-cil", pkgver:"1.0.17.0+OOo3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libuno-cli-uretypes1.0-cil", pkgver:"1.0.3.0+OOo3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"mozilla-openoffice.org", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-base", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-base-core", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-calc", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-common", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-core", pkgver:"1:3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-dev", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-dev-doc", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-draw", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-dtd-officedocument1.0", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-emailmerge", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-evolution", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-filter-binfilter", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-filter-mobiledev", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-gcj", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-gnome", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-gtk", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-impress", pkgver:"1:3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-java-common", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-kde", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-l10n-in", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-l10n-za", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-math", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-officebean", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-ogltrans", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-pdfimport", pkgver:"1.0+OOo3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-presentation-minimizer", pkgver:"1.0+OOo3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-presenter-console", pkgver:"1.1.0+OOo3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-report-builder", pkgver:"1.1.0+OOo3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-report-builder-bin", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-sdbc-postgresql", pkgver:"0.7.6+OOo3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-style-andromeda", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-style-crystal", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-style-galaxy", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-style-hicontrast", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-style-human", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-style-industrial", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-style-oxygen", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-style-tango", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-wiki-publisher", pkgver:"1.0+OOo3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-writer", pkgver:"1:3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"python-uno", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ttf-opensymbol", pkgver:"3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"uno-libs3", pkgver:"1.5.1+OOo3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"uno-libs3-dbg", pkgver:"1.5.1+OOo3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ure", pkgver:"1.5.1+OOo3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ure-dbg", pkgver:"1.5.1+OOo3.1.1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"broffice.org", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"cli-uno-bridge", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libmythes-dev", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libuno-cli-basetypes1.0-cil", pkgver:"1.0.15.0+OOo3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libuno-cli-cppuhelper1.0-cil", pkgver:"1.0.18.0+OOo3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libuno-cli-oootypes1.0-cil", pkgver:"1.0.4.0+OOo3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libuno-cli-ure1.0-cil", pkgver:"1.0.18.0+OOo3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libuno-cli-uretypes1.0-cil", pkgver:"1.0.4.0+OOo3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"mozilla-openoffice.org", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-base", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-base-core", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-calc", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-common", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-core", pkgver:"1:3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-dev", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-dev-doc", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-draw", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-dtd-officedocument1.0", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-emailmerge", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-evolution", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-filter-binfilter", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-filter-mobiledev", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-gcj", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-gnome", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-gtk", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-impress", pkgver:"1:3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-java-common", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-kde", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-l10n-in", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-l10n-za", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-math", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-mysql-connector", pkgver:"1.0.1+OOo3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-officebean", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-ogltrans", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-pdfimport", pkgver:"1.0+OOo3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-presentation-minimizer", pkgver:"1.0+OOo3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-presenter-console", pkgver:"1.1.0+OOo3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-report-builder", pkgver:"1.2.0+OOo3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-report-builder-bin", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-sdbc-postgresql", pkgver:"0.7.6+OOo3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-style-andromeda", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-style-crystal", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-style-galaxy", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-style-hicontrast", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-style-human", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-style-industrial", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-style-oxygen", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-style-tango", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-wiki-publisher", pkgver:"1.1+OOo3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-writer", pkgver:"1:3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"python-uno", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"ttf-opensymbol", pkgver:"3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"uno-libs3", pkgver:"1.6.0+OOo3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"uno-libs3-dbg", pkgver:"1.6.0+OOo3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"ure", pkgver:"1.6.0+OOo3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"ure-dbg", pkgver:"1.6.0+OOo3.2.0-7ubuntu4.2")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"broffice.org", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"cli-uno-bridge", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libuno-cli-basetypes1.0-cil", pkgver:"1.0.17.0+OOo3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libuno-cli-cppuhelper1.0-cil", pkgver:"1.0.20.0+OOo3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libuno-cli-oootypes1.0-cil", pkgver:"1.0.6.0+OOo3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libuno-cli-ure1.0-cil", pkgver:"1.0.20.0+OOo3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libuno-cli-uretypes1.0-cil", pkgver:"1.0.6.0+OOo3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"mozilla-openoffice.org", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-base", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-base-core", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-calc", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-common", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-core", pkgver:"1:3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-dev", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-dev-doc", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-draw", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-dtd-officedocument1.0", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-emailmerge", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-evolution", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-filter-binfilter", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-filter-mobiledev", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-gcj", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-gnome", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-gtk", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-impress", pkgver:"1:3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-java-common", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-kde", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-l10n-in", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-l10n-za", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-math", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-mysql-connector", pkgver:"1.0.1+OOo3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-officebean", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-ogltrans", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-pdfimport", pkgver:"1.0.2+OOo3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-presentation-minimizer", pkgver:"1.0.2+OOo3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-presenter-console", pkgver:"1.1.0+OOo3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-report-builder", pkgver:"1.2.1+OOo3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-report-builder-bin", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-sdbc-postgresql", pkgver:"0.7.6+OOo3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-style-andromeda", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-style-crystal", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-style-galaxy", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-style-hicontrast", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-style-human", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-style-industrial", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-style-oxygen", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-style-tango", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-wiki-publisher", pkgver:"1.1.1+OOo3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openoffice.org-writer", pkgver:"1:3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"python-uno", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"ttf-opensymbol", pkgver:"3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"uno-libs3", pkgver:"1.6.1+OOo3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"uno-libs3-dbg", pkgver:"1.6.1+OOo3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"ure", pkgver:"1.6.1+OOo3.2.1-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"ure-dbg", pkgver:"1.6.1+OOo3.2.1-7ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "broffice.org / cli-uno-bridge / libmythes-dev / libuno-cil / etc");
}
