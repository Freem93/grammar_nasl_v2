#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-712-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38044);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:37:18 $");

  script_cve_id("CVE-2008-2712", "CVE-2008-4101");
  script_osvdb_id(51437);
  script_xref(name:"USN", value:"712-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.10 / 8.04 LTS / 8.10 : vim vulnerabilities (USN-712-1)");
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
"Jan Minar discovered that Vim did not properly sanitize inputs before
invoking the execute or system functions inside Vim scripts. If a user
were tricked into running Vim scripts with a specially crafted input,
an attacker could execute arbitrary code with the privileges of the
user invoking the program. (CVE-2008-2712)

Ben Schmidt discovered that Vim did not properly escape characters
when performing keyword or tag lookups. If a user were tricked into
running specially crafted commands, an attacker could execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2008-4101).

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
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-full");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-gui-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-tiny");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|7\.10|8\.04|8\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.10 / 8.04 / 8.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"vim", pkgver:"1:6.4-006+2ubuntu6.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"vim-common", pkgver:"6.4-006+2ubuntu6.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"vim-doc", pkgver:"6.4-006+2ubuntu6.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"vim-gnome", pkgver:"6.4-006+2ubuntu6.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"vim-gtk", pkgver:"6.4-006+2ubuntu6.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"vim-gui-common", pkgver:"6.4-006+2ubuntu6.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"vim-perl", pkgver:"6.4-006+2ubuntu6.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"vim-python", pkgver:"6.4-006+2ubuntu6.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"vim-ruby", pkgver:"6.4-006+2ubuntu6.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"vim-runtime", pkgver:"1:6.4-006+2ubuntu6.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"vim-tcl", pkgver:"6.4-006+2ubuntu6.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"vim-tiny", pkgver:"6.4-006+2ubuntu6.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"vim", pkgver:"1:7.1-056+2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"vim-common", pkgver:"7.1-056+2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"vim-doc", pkgver:"7.1-056+2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"vim-full", pkgver:"7.1-056+2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"vim-gnome", pkgver:"7.1-056+2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"vim-gtk", pkgver:"7.1-056+2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"vim-gui-common", pkgver:"7.1-056+2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"vim-perl", pkgver:"7.1-056+2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"vim-python", pkgver:"7.1-056+2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"vim-ruby", pkgver:"7.1-056+2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"vim-runtime", pkgver:"1:7.1-056+2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"vim-tcl", pkgver:"7.1-056+2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"vim-tiny", pkgver:"7.1-056+2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"vim", pkgver:"1:7.1-138+1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"vim-common", pkgver:"7.1-138+1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"vim-doc", pkgver:"7.1-138+1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"vim-full", pkgver:"7.1-138+1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"vim-gnome", pkgver:"7.1-138+1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"vim-gtk", pkgver:"7.1-138+1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"vim-gui-common", pkgver:"7.1-138+1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"vim-nox", pkgver:"7.1-138+1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"vim-perl", pkgver:"7.1-138+1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"vim-python", pkgver:"7.1-138+1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"vim-ruby", pkgver:"7.1-138+1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"vim-runtime", pkgver:"1:7.1-138+1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"vim-tcl", pkgver:"7.1-138+1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"vim-tiny", pkgver:"7.1-138+1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"vim", pkgver:"1:7.1.314-3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"vim-common", pkgver:"7.1.314-3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"vim-dbg", pkgver:"7.1.314-3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"vim-doc", pkgver:"7.1.314-3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"vim-full", pkgver:"7.1.314-3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"vim-gnome", pkgver:"7.1.314-3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"vim-gtk", pkgver:"7.1.314-3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"vim-gui-common", pkgver:"7.1.314-3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"vim-nox", pkgver:"7.1.314-3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"vim-perl", pkgver:"7.1.314-3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"vim-python", pkgver:"7.1.314-3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"vim-ruby", pkgver:"7.1.314-3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"vim-runtime", pkgver:"1:7.1.314-3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"vim-tcl", pkgver:"7.1.314-3ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"vim-tiny", pkgver:"7.1.314-3ubuntu3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vim / vim-common / vim-dbg / vim-doc / vim-full / vim-gnome / etc");
}
