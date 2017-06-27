#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-505-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28109);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:29:18 $");

  script_cve_id("CVE-2007-2953");
  script_bugtraq_id(25095);
  script_osvdb_id(38674, 51434);
  script_xref(name:"USN", value:"505-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 : vim vulnerability (USN-505-1)");
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
"Ulf Harnhammar discovered that vim does not properly sanitise the
'helptags_one()' function when running the 'helptags' command. By
tricking a user into running a crafted help file, a remote attacker
could execute arbitrary code with the user's privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-full");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-gui-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-tiny");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/27");
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
if (! ereg(pattern:"^(6\.06|6\.10|7\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 6.10 / 7.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"vim", pkgver:"1:6.4-006+2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"vim-common", pkgver:"6.4-006+2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"vim-doc", pkgver:"6.4-006+2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"vim-gnome", pkgver:"6.4-006+2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"vim-gtk", pkgver:"6.4-006+2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"vim-gui-common", pkgver:"6.4-006+2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"vim-perl", pkgver:"6.4-006+2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"vim-python", pkgver:"6.4-006+2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"vim-ruby", pkgver:"6.4-006+2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"vim-runtime", pkgver:"6.4-006+2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"vim-tcl", pkgver:"6.4-006+2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"vim-tiny", pkgver:"6.4-006+2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"vim", pkgver:"1:7.0-035+1ubuntu5.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"vim-common", pkgver:"7.0-035+1ubuntu5.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"vim-doc", pkgver:"7.0-035+1ubuntu5.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"vim-full", pkgver:"7.0-035+1ubuntu5.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"vim-gnome", pkgver:"7.0-035+1ubuntu5.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"vim-gtk", pkgver:"7.0-035+1ubuntu5.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"vim-gui-common", pkgver:"7.0-035+1ubuntu5.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"vim-perl", pkgver:"7.0-035+1ubuntu5.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"vim-python", pkgver:"7.0-035+1ubuntu5.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"vim-ruby", pkgver:"7.0-035+1ubuntu5.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"vim-runtime", pkgver:"7.0-035+1ubuntu5.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"vim-tcl", pkgver:"7.0-035+1ubuntu5.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"vim-tiny", pkgver:"7.0-035+1ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"vim", pkgver:"1:7.0-164+1ubuntu7.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"vim-common", pkgver:"7.0-164+1ubuntu7.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"vim-doc", pkgver:"7.0-164+1ubuntu7.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"vim-full", pkgver:"7.0-164+1ubuntu7.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"vim-gnome", pkgver:"7.0-164+1ubuntu7.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"vim-gtk", pkgver:"7.0-164+1ubuntu7.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"vim-gui-common", pkgver:"7.0-164+1ubuntu7.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"vim-perl", pkgver:"7.0-164+1ubuntu7.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"vim-python", pkgver:"7.0-164+1ubuntu7.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"vim-ruby", pkgver:"7.0-164+1ubuntu7.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"vim-runtime", pkgver:"7.0-164+1ubuntu7.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"vim-tcl", pkgver:"7.0-164+1ubuntu7.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"vim-tiny", pkgver:"7.0-164+1ubuntu7.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vim / vim-common / vim-doc / vim-full / vim-gnome / vim-gtk / etc");
}
