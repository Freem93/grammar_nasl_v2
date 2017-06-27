#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-409-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27997);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:21:18 $");

  script_cve_id("CVE-2006-6811");
  script_osvdb_id(33443);
  script_xref(name:"USN", value:"409-1");

  script_name(english:"Ubuntu 5.10 / 6.06 LTS / 6.10 : kdenetwork vulnerability (USN-409-1)");
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
"Federico L. Bossi Bonin discovered a Denial of Service vulnerability
in ksirc. By sending a special response packet, a malicious IRC server
could crash ksirc.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dcoprss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdenetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdenetwork-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdenetwork-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdenetwork-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdenetwork-filesharing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdenetwork-kfile-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdict");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdnssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kget");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:knewsticker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kopete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kpf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kppp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ksirc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ktalkd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kwifimanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librss1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librss1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lisa");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/09");
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
if (! ereg(pattern:"^(5\.10|6\.06|6\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.10 / 6.06 / 6.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.10", pkgname:"dcoprss", pkgver:"3.4.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdenetwork", pkgver:"3.4.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdenetwork-doc-html", pkgver:"3.4.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdenetwork-filesharing", pkgver:"3.4.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdenetwork-kfile-plugins", pkgver:"3.4.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdict", pkgver:"3.4.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kget", pkgver:"3.4.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"knewsticker", pkgver:"3.4.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kopete", pkgver:"3.4.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kpf", pkgver:"3.4.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kppp", pkgver:"3.4.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"krdc", pkgver:"3.4.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"krfb", pkgver:"3.4.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"ksirc", pkgver:"4:3.4.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"ktalkd", pkgver:"3.4.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kwifimanager", pkgver:"3.4.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"librss1", pkgver:"3.4.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"librss1-dev", pkgver:"3.4.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"lisa", pkgver:"3.4.3-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"dcoprss", pkgver:"3.5.2-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kdenetwork", pkgver:"3.5.2-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kdenetwork-dev", pkgver:"3.5.2-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kdenetwork-doc-html", pkgver:"3.5.2-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kdenetwork-filesharing", pkgver:"3.5.2-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kdenetwork-kfile-plugins", pkgver:"3.5.2-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kdict", pkgver:"3.5.2-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kdnssd", pkgver:"3.5.2-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kget", pkgver:"3.5.2-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"knewsticker", pkgver:"3.5.2-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kopete", pkgver:"3.5.2-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kpf", pkgver:"3.5.2-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kppp", pkgver:"3.5.2-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krdc", pkgver:"3.5.2-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krfb", pkgver:"3.5.2-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ksirc", pkgver:"4:3.5.2-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ktalkd", pkgver:"3.5.2-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"kwifimanager", pkgver:"3.5.2-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"librss1", pkgver:"3.5.2-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"lisa", pkgver:"3.5.2-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"dcoprss", pkgver:"3.5.5-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kdenetwork", pkgver:"3.5.5-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kdenetwork-dbg", pkgver:"3.5.5-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kdenetwork-dev", pkgver:"3.5.5-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kdenetwork-doc-html", pkgver:"3.5.5-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kdenetwork-filesharing", pkgver:"3.5.5-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kdenetwork-kfile-plugins", pkgver:"3.5.5-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kdict", pkgver:"3.5.5-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kdnssd", pkgver:"3.5.5-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kget", pkgver:"3.5.5-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"knewsticker", pkgver:"3.5.5-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kpf", pkgver:"3.5.5-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kppp", pkgver:"3.5.5-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"krdc", pkgver:"3.5.5-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"krfb", pkgver:"3.5.5-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"ksirc", pkgver:"4:3.5.5-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"ktalkd", pkgver:"3.5.5-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"kwifimanager", pkgver:"3.5.5-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"librss1", pkgver:"3.5.5-0ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"lisa", pkgver:"3.5.5-0ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dcoprss / kdenetwork / kdenetwork-dbg / kdenetwork-dev / etc");
}
