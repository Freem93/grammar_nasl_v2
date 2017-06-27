#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-537-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28144);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:29:18 $");

  script_cve_id("CVE-2007-3920");
  script_osvdb_id(41988);
  script_xref(name:"USN", value:"537-2");

  script_name(english:"Ubuntu 7.10 : compiz vulnerability (USN-537-2)");
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
"USN-537-1 fixed vulnerabilities in gnome-screensaver. The fixes were
incomplete, and only reduced the scope of the vulnerability, without
fully solving it. This update fixes related problems in compiz.

Jens Askengren discovered that gnome-screensaver became confused when
running under Compiz, and could lose keyboard lock focus. A local
attacker could exploit this to bypass the user's locked screen saver.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:compiz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:compiz-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:compiz-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:compiz-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:compiz-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:compiz-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdecoration0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdecoration0-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/01");
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
if (! ereg(pattern:"^(7\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 7.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"7.10", pkgname:"compiz", pkgver:"0.6.0+git20071008-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"compiz-core", pkgver:"1:0.6.0+git20071008-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"compiz-dev", pkgver:"0.6.0+git20071008-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"compiz-gnome", pkgver:"0.6.0+git20071008-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"compiz-kde", pkgver:"0.6.0+git20071008-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"compiz-plugins", pkgver:"0.6.0+git20071008-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libdecoration0", pkgver:"0.6.0+git20071008-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libdecoration0-dev", pkgver:"0.6.0+git20071008-0ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "compiz / compiz-core / compiz-dev / compiz-gnome / compiz-kde / etc");
}
