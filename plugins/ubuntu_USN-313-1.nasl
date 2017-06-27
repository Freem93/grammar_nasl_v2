#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-313-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27888);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/27 14:21:17 $");

  script_cve_id("CVE-2006-2198", "CVE-2006-2199", "CVE-2006-3117");
  script_osvdb_id(26939, 26940, 26941, 26942, 26943, 26944, 26945);
  script_xref(name:"USN", value:"313-1");

  script_name(english:"Ubuntu 5.04 / 6.06 LTS : openoffice.org-amd64, openoffice.org vulnerabilities (USN-313-1)");
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
"It was possible to embed Basic macros in documents in a way that
OpenOffice.org would not ask for confirmation about executing them. By
tricking a user into opening a malicious document, this could be
exploited to run arbitrary Basic code (including local file access and
modification) with the user's privileges. (CVE-2006-2198)

A flaw was discovered in the Java sandbox which allowed Java applets
to break out of the sandbox and execute code without restrictions. By
tricking a user into opening a malicious document, this could be
exploited to run arbitrary code with the user's privileges. This
update disables Java applets for OpenOffice.org, since it is not
generally possible to guarantee the sandbox restrictions.
(CVE-2006-2199)

A buffer overflow has been found in the XML parser. By tricking a user
into opening a specially crafted XML file with OpenOffice.org, this
could be exploited to execute arbitrary code with the user's
privileges. (CVE-2006-3117).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmythes-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-bin");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-gnomevfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-gtk-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-java-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-en-us");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-ns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-pt-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-zh-cn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-zh-tw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-l10n-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-mimelnk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-qa-api-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-qa-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-thesaurus-en-us");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openoffice.org2-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-uno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ttf-opensymbol");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2006-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5\.04|6\.06)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.04 / 6.06", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-bin", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-dev", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-evolution", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-gnomevfs", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-gtk-gnome", pkgver:"1.1.3-8ubuntu2.4-1")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-kde", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-af", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-ar", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-ca", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-cs", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-cy", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-da", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-de", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-el", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-en", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-es", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-et", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-eu", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-fi", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-fr", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-gl", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-he", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-hi", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-hu", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-it", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-ja", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-kn", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-ko", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-lt", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-nb", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-nl", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-nn", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-ns", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-pl", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-pt", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-pt-br", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-ru", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-sk", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-sl", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-sv", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-th", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-tn", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-tr", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-xh", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-zh-cn", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-zh-tw", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-l10n-zu", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-mimelnk", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openoffice.org-thesaurus-en-us", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"ttf-opensymbol", pkgver:"1.1.3-8ubuntu2.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libmythes-dev", pkgver:"2.0.2-2ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org", pkgver:"2.0.2-2ubuntu12.1-1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-base", pkgver:"2.0.2-2ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-calc", pkgver:"2.0.2-2ubuntu12.1-1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-common", pkgver:"2.0.2-2ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-core", pkgver:"2.0.2-2ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-dev", pkgver:"2.0.2-2ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-dev-doc", pkgver:"2.0.2-2ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-draw", pkgver:"2.0.2-2ubuntu12.1-1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-evolution", pkgver:"2.0.2-2ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-filter-so52", pkgver:"2.0.2-2ubuntu12.1-1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-gcj", pkgver:"2.0.2-2ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-gnome", pkgver:"2.0.2-2ubuntu12.1-1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-gtk", pkgver:"2.0.2-2ubuntu12.1-1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-gtk-gnome", pkgver:"2.0.2-2ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-impress", pkgver:"2.0.2-2ubuntu12.1-1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-java-common", pkgver:"2.0.2-2ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-kde", pkgver:"2.0.2-2ubuntu12.1-1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-l10n-en-us", pkgver:"2.0.2-2ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-math", pkgver:"2.0.2-2ubuntu12.1-1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-officebean", pkgver:"2.0.2-2ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-qa-api-tests", pkgver:"2.0.2-2ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-qa-tools", pkgver:"2.0.2-2ubuntu12.1-1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org-writer", pkgver:"2.0.2-2ubuntu12.1-1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2", pkgver:"2.0.2-2ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2-base", pkgver:"2.0.2-2ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2-calc", pkgver:"2.0.2-2ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2-draw", pkgver:"2.0.2-2ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2-evolution", pkgver:"2.0.2-2ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2-gnome", pkgver:"2.0.2-2ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2-impress", pkgver:"2.0.2-2ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2-kde", pkgver:"2.0.2-2ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2-math", pkgver:"2.0.2-2ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openoffice.org2-writer", pkgver:"2.0.2-2ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python-uno", pkgver:"2.0.2-2ubuntu12.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ttf-opensymbol", pkgver:"2.0.2-2ubuntu12.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmythes-dev / openoffice.org / openoffice.org-base / etc");
}
