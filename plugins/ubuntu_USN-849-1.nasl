#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-849-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42167);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/27 14:45:42 $");

  script_cve_id("CVE-2009-1788", "CVE-2009-1791");
  script_bugtraq_id(34978);
  script_xref(name:"USN", value:"849-1");

  script_name(english:"Ubuntu 8.04 LTS / 8.10 / 9.04 : libsndfile vulnerabilities (USN-849-1)");
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
"Tobias Klein discovered a heap-based buffer overflow in libsndfile. If
a user or automated system processed a crafted VOC file, an attacker
could cause a denial of service via application crash, or possibly
execute arbitrary code with the privileges of the user invoking the
program. (CVE-2009-1788)

Erik de Castro Lopo discovered a similar heap-based buffer overflow
when processing AIFF files. If a user or automated system processed a
crafted AIFF file, an attacker could cause a denial of service via
application crash, or possibly execute arbitrary code with the
privileges of the user invoking the program. (CVE-2009-1791).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libsndfile1, libsndfile1-dev and / or
sndfile-programs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsndfile1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsndfile1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sndfile-programs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/16");
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
if (! ereg(pattern:"^(8\.04|8\.10|9\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 8.10 / 9.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"libsndfile1", pkgver:"1.0.17-4ubuntu0.8.04.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsndfile1-dev", pkgver:"1.0.17-4ubuntu0.8.04.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"sndfile-programs", pkgver:"1.0.17-4ubuntu0.8.04.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libsndfile1", pkgver:"1.0.17-4ubuntu0.8.10.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libsndfile1-dev", pkgver:"1.0.17-4ubuntu0.8.10.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"sndfile-programs", pkgver:"1.0.17-4ubuntu0.8.10.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libsndfile1", pkgver:"1.0.17-4ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libsndfile1-dev", pkgver:"1.0.17-4ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"sndfile-programs", pkgver:"1.0.17-4ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsndfile1 / libsndfile1-dev / sndfile-programs");
}
