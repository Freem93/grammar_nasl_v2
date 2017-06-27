#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-406-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27994);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:21:18 $");

  script_cve_id("CVE-2006-5870");
  script_bugtraq_id(21861);
  script_xref(name:"USN", value:"406-1");

  script_name(english:"Ubuntu 5.10 / 6.06 LTS : openoffice.org/-amd64, openoffice.org2/-amd64 vulnerability (USN-406-1)");
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
"An integer overflow was discovered in OpenOffice.org's handling of WMF
files. If a user were tricked into opening a specially crafted WMF
file, an attacker could execute arbitrary code with user privileges.

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

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmythes-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-openoffice.org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-dev-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-filter-so52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-gcj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-gtk-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-java-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-en-us");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-qa-api-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-qa-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-dev-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-filter-so52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-java-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-l10n-en-us");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-uno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ttf-opensymbol");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
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
if (! ereg(pattern:"^(5\.10|6\.06)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.10 / 6.06", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.10", pkgname:"mozilla-openoffice.org", pkgver:"1.9.129-0.1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2", pkgver:"1.9.129-0.1ubuntu4.2-1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-base", pkgver:"1.9.129-0.1ubuntu4.2-1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-calc", pkgver:"1.9.129-0.1ubuntu4.2-1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-common", pkgver:"1.9.129-0.1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-core", pkgver:"1.9.129-0.1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-dev", pkgver:"1.9.129-0.1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-dev-doc", pkgver:"1.9.129-0.1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-draw", pkgver:"1.9.129-0.1ubuntu4.2-1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-evolution", pkgver:"1.9.129-0.1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-filter-so52", pkgver:"1.9.129-0.1ubuntu4.2-1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-gnome", pkgver:"1.9.129-0.1ubuntu4.2-1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-impress", pkgver:"1.9.129-0.1ubuntu4.2-1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-java-common", pkgver:"1.9.129-0.1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-kde", pkgver:"1.9.129-0.1ubuntu4.2-1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-l10n-en-us", pkgver:"1.9.129-0.1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-math", pkgver:"1.9.129-0.1ubuntu4.2-1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-officebean", pkgver:"1.9.129-0.1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-writer", pkgver:"1.9.129-0.1ubuntu4.2-1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python-uno", pkgver:"1.9.129-0.1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"ttf-opensymbol", pkgver:"1.9.129-0.1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libmythes-dev", pkgver:"2.0.2-2ubuntu12.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org", pkgver:"2.0.2-2ubuntu12.2-1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-base", pkgver:"2.0.2-2ubuntu12.2-1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-calc", pkgver:"2.0.2-2ubuntu12.2-1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-common", pkgver:"2.0.2-2ubuntu12.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-core", pkgver:"2.0.2-2ubuntu12.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-dev", pkgver:"2.0.2-2ubuntu12.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-dev-doc", pkgver:"2.0.2-2ubuntu12.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-draw", pkgver:"2.0.2-2ubuntu12.2-1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-evolution", pkgver:"2.0.2-2ubuntu12.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-filter-so52", pkgver:"2.0.2-2ubuntu12.2-1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-gcj", pkgver:"2.0.2-2ubuntu12.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-gnome", pkgver:"2.0.2-2ubuntu12.2-1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-gtk", pkgver:"2.0.2-2ubuntu12.2-1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-gtk-gnome", pkgver:"2.0.2-2ubuntu12.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-impress", pkgver:"2.0.2-2ubuntu12.2-1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-java-common", pkgver:"2.0.2-2ubuntu12.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-kde", pkgver:"2.0.2-2ubuntu12.2-1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-l10n-en-us", pkgver:"2.0.2-2ubuntu12.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-math", pkgver:"2.0.2-2ubuntu12.2-1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-officebean", pkgver:"2.0.2-2ubuntu12.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-qa-api-tests", pkgver:"2.0.2-2ubuntu12.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-qa-tools", pkgver:"2.0.2-2ubuntu12.2-1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-writer", pkgver:"2.0.2-2ubuntu12.2-1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2", pkgver:"2.0.2-2ubuntu12.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2-base", pkgver:"2.0.2-2ubuntu12.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2-calc", pkgver:"2.0.2-2ubuntu12.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2-draw", pkgver:"2.0.2-2ubuntu12.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2-evolution", pkgver:"2.0.2-2ubuntu12.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2-gnome", pkgver:"2.0.2-2ubuntu12.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2-impress", pkgver:"2.0.2-2ubuntu12.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2-kde", pkgver:"2.0.2-2ubuntu12.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2-math", pkgver:"2.0.2-2ubuntu12.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2-writer", pkgver:"2.0.2-2ubuntu12.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python-uno", pkgver:"2.0.2-2ubuntu12.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ttf-opensymbol", pkgver:"2.0.2-2ubuntu12.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmythes-dev / mozilla-openoffice.org / openoffice.org / etc");
}
