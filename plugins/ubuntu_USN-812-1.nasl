#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-812-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40528);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:37:19 $");

  script_cve_id("CVE-2009-2411");
  script_bugtraq_id(35983);
  script_osvdb_id(56856);
  script_xref(name:"USN", value:"812-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 / 9.04 : subversion vulnerability (USN-812-1)");
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
"Matt Lewis discovered that Subversion did not properly sanitize its
input when processing svndiff streams, leading to various integer and
heap overflows. If a user or automated system processed crafted input,
a remote attacker could cause a denial of service or potentially
execute arbitrary code as the user processing the input.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn-core-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn-javahl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsvn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-subversion-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/10");
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
if (! ereg(pattern:"^(6\.06|8\.04|8\.10|9\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 8.10 / 9.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libapache2-svn", pkgver:"1.3.1-3ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libsvn-core-perl", pkgver:"1.3.1-3ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libsvn-doc", pkgver:"1.3.1-3ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libsvn-javahl", pkgver:"1.3.1-3ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libsvn-ruby", pkgver:"1.3.1-3ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libsvn-ruby1.8", pkgver:"1.3.1-3ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libsvn0", pkgver:"1.3.1-3ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libsvn0-dev", pkgver:"1.3.1-3ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python-subversion", pkgver:"1.3.1-3ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-subversion", pkgver:"1.3.1-3ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"subversion", pkgver:"1.3.1-3ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"subversion-tools", pkgver:"1.3.1-3ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libapache2-svn", pkgver:"1.4.6dfsg1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsvn-dev", pkgver:"1.4.6dfsg1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsvn-doc", pkgver:"1.4.6dfsg1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsvn-java", pkgver:"1.4.6dfsg1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsvn-javahl", pkgver:"1.4.6dfsg1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsvn-perl", pkgver:"1.4.6dfsg1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsvn-ruby", pkgver:"1.4.6dfsg1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsvn-ruby1.8", pkgver:"1.4.6dfsg1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsvn1", pkgver:"1.4.6dfsg1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python-subversion", pkgver:"1.4.6dfsg1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python-subversion-dbg", pkgver:"1.4.6dfsg1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"subversion", pkgver:"1.4.6dfsg1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"subversion-tools", pkgver:"1.4.6dfsg1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libapache2-svn", pkgver:"1.5.1dfsg1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libsvn-dev", pkgver:"1.5.1dfsg1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libsvn-doc", pkgver:"1.5.1dfsg1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libsvn-java", pkgver:"1.5.1dfsg1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libsvn-perl", pkgver:"1.5.1dfsg1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libsvn-ruby", pkgver:"1.5.1dfsg1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libsvn-ruby1.8", pkgver:"1.5.1dfsg1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libsvn1", pkgver:"1.5.1dfsg1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"python-subversion", pkgver:"1.5.1dfsg1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"python-subversion-dbg", pkgver:"1.5.1dfsg1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"subversion", pkgver:"1.5.1dfsg1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"subversion-tools", pkgver:"1.5.1dfsg1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libapache2-svn", pkgver:"1.5.4dfsg1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libsvn-dev", pkgver:"1.5.4dfsg1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libsvn-doc", pkgver:"1.5.4dfsg1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libsvn-java", pkgver:"1.5.4dfsg1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libsvn-perl", pkgver:"1.5.4dfsg1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libsvn-ruby", pkgver:"1.5.4dfsg1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libsvn-ruby1.8", pkgver:"1.5.4dfsg1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libsvn1", pkgver:"1.5.4dfsg1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"python-subversion", pkgver:"1.5.4dfsg1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"python-subversion-dbg", pkgver:"1.5.4dfsg1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"subversion", pkgver:"1.5.4dfsg1-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"subversion-tools", pkgver:"1.5.4dfsg1-1ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapache2-svn / libsvn-core-perl / libsvn-dev / libsvn-doc / etc");
}
