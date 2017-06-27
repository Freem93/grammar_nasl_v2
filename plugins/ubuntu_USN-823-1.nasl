#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-823-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65118);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2009-0945", "CVE-2009-1709");
  script_bugtraq_id(34924, 35334);
  script_xref(name:"USN", value:"823-1");

  script_name(english:"Ubuntu 8.04 LTS : kdegraphics vulnerabilities (USN-823-1)");
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
"It was discovered that KDE-Graphics did not properly handle certain
malformed SVG images. If a user were tricked into opening a specially
crafted SVG image, an attacker could cause a denial of service or
possibly execute arbitrary code with the privileges of the user
invoking the program.

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
  script_cwe_id(94, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kamera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kcoloredit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdegraphics-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdegraphics-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdegraphics-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdegraphics-kfile-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdvi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kfax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kfaxview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kgamma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kghostview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kiconedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kmrml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kolourpaint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kooka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kpdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kpovmodeler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kruler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ksnapshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ksvg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kviewshell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkscan-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkscan1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2016 Canonical, Inc. / NASL script (C) 2013-2016 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"8.04", pkgname:"kamera", pkgver:"3.5.10-0ubuntu1~hardy1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kcoloredit", pkgver:"3.5.10-0ubuntu1~hardy1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kdegraphics", pkgver:"3.5.10-0ubuntu1~hardy1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kdegraphics-dbg", pkgver:"3.5.10-0ubuntu1~hardy1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kdegraphics-dev", pkgver:"3.5.10-0ubuntu1~hardy1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kdegraphics-doc-html", pkgver:"3.5.10-0ubuntu1~hardy1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kdegraphics-kfile-plugins", pkgver:"3.5.10-0ubuntu1~hardy1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kdvi", pkgver:"3.5.10-0ubuntu1~hardy1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kfax", pkgver:"3.5.10-0ubuntu1~hardy1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kfaxview", pkgver:"3.5.10-0ubuntu1~hardy1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kgamma", pkgver:"3.5.10-0ubuntu1~hardy1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kghostview", pkgver:"3.5.10-0ubuntu1~hardy1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kiconedit", pkgver:"3.5.10-0ubuntu1~hardy1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kmrml", pkgver:"3.5.10-0ubuntu1~hardy1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kolourpaint", pkgver:"3.5.10-0ubuntu1~hardy1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kooka", pkgver:"3.5.10-0ubuntu1~hardy1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kpdf", pkgver:"3.5.10-0ubuntu1~hardy1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kpovmodeler", pkgver:"3.5.10-0ubuntu1~hardy1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kruler", pkgver:"3.5.10-0ubuntu1~hardy1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ksnapshot", pkgver:"3.5.10-0ubuntu1~hardy1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ksvg", pkgver:"4:3.5.10-0ubuntu1~hardy1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kview", pkgver:"3.5.10-0ubuntu1~hardy1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"kviewshell", pkgver:"3.5.10-0ubuntu1~hardy1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libkscan-dev", pkgver:"3.5.10-0ubuntu1~hardy1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libkscan1", pkgver:"3.5.10-0ubuntu1~hardy1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kamera / kcoloredit / kdegraphics / kdegraphics-dbg / etc");
}
