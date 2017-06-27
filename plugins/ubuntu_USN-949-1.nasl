#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-949-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46836);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/27 14:45:44 $");

  script_cve_id("CVE-2010-0395");
  script_xref(name:"USN", value:"949-1");

  script_name(english:"Ubuntu 8.04 LTS / 9.04 / 9.10 / 10.04 LTS : openoffice.org vulnerability (USN-949-1)");
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
"Marc Schoenefeld discovered that OpenOffice.org would run document
macros from the macro browser, even when macros were disabled. If a
user were tricked into opening a specially crafted document and
examining a macro, a remote attacker could execute arbitrary code with
user privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-kab");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2010-2016 Canonical, Inc. / NASL script (C) 2010-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(8\.04|9\.04|9\.10|10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 9.04 / 9.10 / 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"broffice.org", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libmythes-dev", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libuno-cil", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mozilla-openoffice.org", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-base", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-base-core", pkgver:"1:2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-calc", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-common", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-core", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-dev", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-dev-doc", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-draw", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-dtd-officedocument1.0", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-evolution", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-filter-binfilter", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-filter-mobiledev", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-gcj", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-gnome", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-gtk", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-headless", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-impress", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-java-common", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-kde", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-in", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-l10n-za", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-math", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-officebean", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-ogltrans", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-presentation-minimizer", pkgver:"1.0+OOo2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-qa-api-tests", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-qa-tools", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-report-builder", pkgver:"1.0.2+OOo2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-sdbc-postgresql", pkgver:"0.7.5+OOo2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-style-andromeda", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-style-crystal", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-style-hicontrast", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-style-human", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-style-industrial", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-style-tango", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openoffice.org-writer", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python-uno", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ttf-opensymbol", pkgver:"2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ure", pkgver:"1.4+OOo2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ure-dbg", pkgver:"1.4+OOo2.4.1-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"broffice.org", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"cli-uno-bridge", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libmythes-dev", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libuno-cli-basetypes1.0-cil", pkgver:"1.0.12.0+OOo3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libuno-cli-cppuhelper1.0-cil", pkgver:"1.0.15.0+OOo3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libuno-cli-oootypes1.0-cil", pkgver:"1.0.1.0+OOo3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libuno-cli-ure1.0-cil", pkgver:"1.0.15.0+OOo3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libuno-cli-uretypes1.0-cil", pkgver:"1.0.1.0+OOo3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mozilla-openoffice.org", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-base", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-base-core", pkgver:"1:3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-calc", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-common", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-core", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-dev", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-dev-doc", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-draw", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-dtd-officedocument1.0", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-emailmerge", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-evolution", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-filter-binfilter", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-filter-mobiledev", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-gcj", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-gnome", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-gtk", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-impress", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-java-common", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-kab", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-kde", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-l10n-in", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-l10n-za", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-math", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-officebean", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-pdfimport", pkgver:"0.3.2+OOo3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-presentation-minimizer", pkgver:"1.0+OOo3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-presenter-console", pkgver:"1.0+OOo3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-report-builder", pkgver:"1.0.5+OOo3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-report-builder-bin", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-sdbc-postgresql", pkgver:"0.7.6+OOo3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-style-andromeda", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-style-crystal", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-style-galaxy", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-style-hicontrast", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-style-human", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-style-industrial", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-style-tango", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-wiki-publisher", pkgver:"1.0+OOo3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"openoffice.org-writer", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"python-uno", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ttf-opensymbol", pkgver:"3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"uno-libs3", pkgver:"1.4.1+OOo3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"uno-libs3-dbg", pkgver:"1.4.1+OOo3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ure", pkgver:"1.4.1+OOo3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ure-dbg", pkgver:"1.4.1+OOo3.0.1-9ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"broffice.org", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"cli-uno-bridge", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libmythes-dev", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libuno-cli-basetypes1.0-cil", pkgver:"1.0.14.0+OOo3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libuno-cli-cppuhelper1.0-cil", pkgver:"1.0.17.0+OOo3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libuno-cli-oootypes1.0-cil", pkgver:"1.0.3.0+OOo3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libuno-cli-ure1.0-cil", pkgver:"1.0.17.0+OOo3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libuno-cli-uretypes1.0-cil", pkgver:"1.0.3.0+OOo3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"mozilla-openoffice.org", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-base", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-base-core", pkgver:"1:3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-calc", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-common", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-core", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-dev", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-dev-doc", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-draw", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-dtd-officedocument1.0", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-emailmerge", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-evolution", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-filter-binfilter", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-filter-mobiledev", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-gcj", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-gnome", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-gtk", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-impress", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-java-common", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-kde", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-l10n-in", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-l10n-za", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-math", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-officebean", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-ogltrans", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-pdfimport", pkgver:"1.0+OOo3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-presentation-minimizer", pkgver:"1.0+OOo3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-presenter-console", pkgver:"1.1.0+OOo3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-report-builder", pkgver:"1.1.0+OOo3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-report-builder-bin", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-sdbc-postgresql", pkgver:"0.7.6+OOo3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-style-andromeda", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-style-crystal", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-style-galaxy", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-style-hicontrast", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-style-human", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-style-industrial", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-style-oxygen", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-style-tango", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-wiki-publisher", pkgver:"1.0+OOo3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"openoffice.org-writer", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"python-uno", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ttf-opensymbol", pkgver:"3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"uno-libs3", pkgver:"1.5.1+OOo3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"uno-libs3-dbg", pkgver:"1.5.1+OOo3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ure", pkgver:"1.5.1+OOo3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"ure-dbg", pkgver:"1.5.1+OOo3.1.1-5ubuntu1.2")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"broffice.org", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"cli-uno-bridge", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libmythes-dev", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libuno-cli-basetypes1.0-cil", pkgver:"1.0.15.0+OOo3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libuno-cli-cppuhelper1.0-cil", pkgver:"1.0.18.0+OOo3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libuno-cli-oootypes1.0-cil", pkgver:"1.0.4.0+OOo3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libuno-cli-ure1.0-cil", pkgver:"1.0.18.0+OOo3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libuno-cli-uretypes1.0-cil", pkgver:"1.0.4.0+OOo3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"mozilla-openoffice.org", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-base", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-base-core", pkgver:"1:3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-calc", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-common", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-core", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-dev", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-dev-doc", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-draw", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-dtd-officedocument1.0", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-emailmerge", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-evolution", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-filter-binfilter", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-filter-mobiledev", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-gcj", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-gnome", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-gtk", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-impress", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-java-common", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-kde", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-l10n-in", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-l10n-za", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-math", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-mysql-connector", pkgver:"1.0.1+OOo3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-officebean", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-ogltrans", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-pdfimport", pkgver:"1.0+OOo3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-presentation-minimizer", pkgver:"1.0+OOo3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-presenter-console", pkgver:"1.1.0+OOo3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-report-builder", pkgver:"1.2.0+OOo3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-report-builder-bin", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-sdbc-postgresql", pkgver:"0.7.6+OOo3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-style-andromeda", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-style-crystal", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-style-galaxy", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-style-hicontrast", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-style-human", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-style-industrial", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-style-oxygen", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-style-tango", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-wiki-publisher", pkgver:"1.1+OOo3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openoffice.org-writer", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"python-uno", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"ttf-opensymbol", pkgver:"3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"uno-libs3", pkgver:"1.6.0+OOo3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"uno-libs3-dbg", pkgver:"1.6.0+OOo3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"ure", pkgver:"1.6.0+OOo3.2.0-7ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"ure-dbg", pkgver:"1.6.0+OOo3.2.0-7ubuntu4.1")) flag++;

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
