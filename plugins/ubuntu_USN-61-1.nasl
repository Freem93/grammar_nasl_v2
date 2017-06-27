#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-61-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20680);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/27 14:29:19 $");

  script_cve_id("CVE-2005-0069");
  script_xref(name:"USN", value:"61-1");

  script_name(english:"Ubuntu 4.10 : vim vulnerabilities (USN-61-1)");
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
"Javier Fernandez-Sanguino Pena noticed that the auxillary scripts
'tcltags' and 'vimspell.sh' created temporary files in an insecure
manner. This could allow a symbolic link attack to create or overwrite
arbitrary files with the privileges of the user invoking the script
(either by calling it directly or by execution through vim).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kvim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-lesstif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-tcl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2005-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"kvim", pkgver:"6.3-025+1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"vim", pkgver:"6.3-025+1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"vim-common", pkgver:"6.3-025+1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"vim-doc", pkgver:"6.3-025+1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"vim-gnome", pkgver:"6.3-025+1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"vim-gtk", pkgver:"6.3-025+1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"vim-lesstif", pkgver:"6.3-025+1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"vim-perl", pkgver:"6.3-025+1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"vim-python", pkgver:"6.3-025+1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"vim-tcl", pkgver:"6.3-025+1ubuntu2.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kvim / vim / vim-common / vim-doc / vim-gnome / vim-gtk / etc");
}
