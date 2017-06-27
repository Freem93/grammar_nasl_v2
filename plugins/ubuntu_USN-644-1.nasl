#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-644-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(37936);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2008-3281", "CVE-2008-3529");
  script_bugtraq_id(30783);
  script_osvdb_id(47636, 48158);
  script_xref(name:"USN", value:"644-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.04 / 7.10 / 8.04 LTS : libxml2 vulnerabilities (USN-644-1)");
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
"It was discovered that libxml2 did not correctly handle long entity
names. If a user were tricked into processing a specially crafted XML
document, a remote attacker could execute arbitrary code with user
privileges or cause the application linked against libxml2 to crash,
leading to a denial of service. (CVE-2008-3529)

USN-640-1 fixed vulnerabilities in libxml2. When processing extremely
large XML documents with valid entities, it was possible to
incorrectly trigger the newly added vulnerability protections. This
update fixes the problem. (CVE-2008-3281).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxml2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxml2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxml2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxml2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-libxml2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-libxml2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|7\.04|7\.10|8\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.04 / 7.10 / 8.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libxml2", pkgver:"2.6.24.dfsg-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libxml2-dbg", pkgver:"2.6.24.dfsg-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libxml2-dev", pkgver:"2.6.24.dfsg-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libxml2-doc", pkgver:"2.6.24.dfsg-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libxml2-utils", pkgver:"2.6.24.dfsg-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python-libxml2", pkgver:"2.6.24.dfsg-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-libxml2", pkgver:"2.6.24.dfsg-1ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libxml2", pkgver:"2.6.27.dfsg-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libxml2-dbg", pkgver:"2.6.27.dfsg-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libxml2-dev", pkgver:"2.6.27.dfsg-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libxml2-doc", pkgver:"2.6.27.dfsg-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libxml2-utils", pkgver:"2.6.27.dfsg-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"python-libxml2", pkgver:"2.6.27.dfsg-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"python-libxml2-dbg", pkgver:"2.6.27.dfsg-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxml2", pkgver:"2.6.30.dfsg-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxml2-dbg", pkgver:"2.6.30.dfsg-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxml2-dev", pkgver:"2.6.30.dfsg-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxml2-doc", pkgver:"2.6.30.dfsg-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libxml2-utils", pkgver:"2.6.30.dfsg-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"python-libxml2", pkgver:"2.6.30.dfsg-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"python-libxml2-dbg", pkgver:"2.6.30.dfsg-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxml2", pkgver:"2.6.31.dfsg-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxml2-dbg", pkgver:"2.6.31.dfsg-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxml2-dev", pkgver:"2.6.31.dfsg-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxml2-doc", pkgver:"2.6.31.dfsg-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libxml2-utils", pkgver:"2.6.31.dfsg-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python-libxml2", pkgver:"2.6.31.dfsg-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python-libxml2-dbg", pkgver:"2.6.31.dfsg-2ubuntu1.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2 / libxml2-dbg / libxml2-dev / libxml2-doc / libxml2-utils / etc");
}
