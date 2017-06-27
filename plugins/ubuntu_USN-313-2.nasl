#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-313-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27889);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/27 14:21:17 $");

  script_cve_id("CVE-2006-2198", "CVE-2006-2199", "CVE-2006-3117");
  script_xref(name:"USN", value:"313-2");

  script_name(english:"Ubuntu 5.10 : openoffice.org2-amd64, openoffice.org2 vulnerabilities (USN-313-2)");
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
"USN-313-1 fixed several vulnerabilities in OpenOffice for Ubuntu 5.04
and Ubuntu 6.06 LTS. This followup advisory provides the corresponding
update for Ubuntu 5.10.

For reference, these are the details of the original USN :

It was possible to embed Basic macros in documents in a way that
OpenOffice.org would not ask for confirmation about executing them. By
tricking a user into opening a malicious document, this could be
exploited to run arbitrary Basic code (including local file access and
modification) with the user's privileges. (CVE-2006-2198)

A flaw was discovered in the Java sandbox which allowed Java
applets to break out of the sandbox and execute code without
restrictions. By tricking a user into opening a malicious
document, this could be exploited to run arbitrary code with
the user's privileges. This update disables Java applets for
OpenOffice.org, since it is not generally possible to
guarantee the sandbox restrictions. (CVE-2006-2199)

A buffer overflow has been found in the XML parser. By
tricking a user into opening a specially crafted XML file
with OpenOffice.org, this could be exploited to execute
arbitrary code with the user's privileges. (CVE-2006-3117).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-openoffice.org");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
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
if (! ereg(pattern:"^(5\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.10", pkgname:"mozilla-openoffice.org", pkgver:"1.9.129-0.1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2", pkgver:"1.9.129-0.1ubuntu4.1-1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-base", pkgver:"1.9.129-0.1ubuntu4.1-1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-calc", pkgver:"1.9.129-0.1ubuntu4.1-1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-common", pkgver:"1.9.129-0.1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-core", pkgver:"1.9.129-0.1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-dev", pkgver:"1.9.129-0.1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-dev-doc", pkgver:"1.9.129-0.1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-draw", pkgver:"1.9.129-0.1ubuntu4.1-1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-evolution", pkgver:"1.9.129-0.1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-filter-so52", pkgver:"1.9.129-0.1ubuntu4.1-1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-gnome", pkgver:"1.9.129-0.1ubuntu4.1-1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-impress", pkgver:"1.9.129-0.1ubuntu4.1-1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-java-common", pkgver:"1.9.129-0.1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-kde", pkgver:"1.9.129-0.1ubuntu4.1-1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-l10n-en-us", pkgver:"1.9.129-0.1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-math", pkgver:"1.9.129-0.1ubuntu4.1-1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-officebean", pkgver:"1.9.129-0.1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openoffice.org2-writer", pkgver:"1.9.129-0.1ubuntu4.1-1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python-uno", pkgver:"1.9.129-0.1ubuntu4.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"ttf-opensymbol", pkgver:"1.9.129-0.1ubuntu4.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mozilla-openoffice.org / openoffice.org2 / openoffice.org2-base / etc");
}
