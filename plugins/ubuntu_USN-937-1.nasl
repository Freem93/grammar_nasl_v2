#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-937-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46254);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/27 14:45:44 $");

  script_cve_id("CVE-2009-1284", "CVE-2010-0739", "CVE-2010-0827", "CVE-2010-1440");
  script_bugtraq_id(34332, 39500);
  script_osvdb_id(53562, 63808, 64388, 64389);
  script_xref(name:"USN", value:"937-1");

  script_name(english:"Ubuntu 8.04 LTS / 9.04 / 9.10 / 10.04 LTS : texlive-bin vulnerabilities (USN-937-1)");
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
"It was discovered that TeX Live incorrectly handled certain long .bib
bibliography files. If a user or automated system were tricked into
processing a specially crafted bib file, an attacker could cause a
denial of service via application crash. This issue only affected
Ubuntu 8.04 LTS, 9.04 and 9.10. (CVE-2009-1284)

Marc Schoenefeld, Karel Srot and Ludwig Nussel discovered that TeX
Live incorrectly handled certain malformed dvi files. If a user or
automated system were tricked into processing a specially crafted dvi
file, an attacker could cause a denial of service via application
crash, or possibly execute arbitrary code with the privileges of the
user invoking the program. (CVE-2010-0739, CVE-2010-1440)

Dan Rosenberg discovered that TeX Live incorrectly handled certain
malformed dvi files. If a user or automated system were tricked into
processing a specially crafted dvi file, an attacker could cause a
denial of service via application crash, or possibly execute arbitrary
code with the privileges of the user invoking the program.
(CVE-2010-0827).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkpathsea-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkpathsea4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkpathsea5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:texlive-base-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:texlive-base-bin-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:texlive-binaries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:texlive-extra-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:texlive-font-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:texlive-lang-indic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:texlive-metapost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:texlive-metapost-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:texlive-music");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:texlive-omega");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:texlive-xetex");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2010-2016 Canonical, Inc. / NASL script (C) 2010-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(8\.04|9\.04|9\.10|10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 9.04 / 9.10 / 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"libkpathsea-dev", pkgver:"2007.dfsg.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libkpathsea4", pkgver:"2007.dfsg.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"texlive-base-bin", pkgver:"2007.dfsg.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"texlive-base-bin-doc", pkgver:"2007.dfsg.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"texlive-extra-utils", pkgver:"2007.dfsg.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"texlive-font-utils", pkgver:"2007.dfsg.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"texlive-lang-indic", pkgver:"2007.dfsg.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"texlive-metapost", pkgver:"2007.dfsg.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"texlive-metapost-doc", pkgver:"2007.dfsg.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"texlive-music", pkgver:"2007.dfsg.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"texlive-omega", pkgver:"2007.dfsg.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"texlive-xetex", pkgver:"2007.dfsg.1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libkpathsea-dev", pkgver:"2007.dfsg.2-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libkpathsea4", pkgver:"2007.dfsg.2-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"texlive-base-bin", pkgver:"2007.dfsg.2-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"texlive-base-bin-doc", pkgver:"2007.dfsg.2-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"texlive-extra-utils", pkgver:"2007.dfsg.2-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"texlive-font-utils", pkgver:"2007.dfsg.2-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"texlive-lang-indic", pkgver:"2007.dfsg.2-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"texlive-metapost", pkgver:"2007.dfsg.2-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"texlive-metapost-doc", pkgver:"2007.dfsg.2-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"texlive-music", pkgver:"2007.dfsg.2-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"texlive-omega", pkgver:"2007.dfsg.2-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"texlive-xetex", pkgver:"2007.dfsg.2-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkpathsea-dev", pkgver:"2007.dfsg.2-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libkpathsea4", pkgver:"2007.dfsg.2-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"texlive-base-bin", pkgver:"2007.dfsg.2-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"texlive-base-bin-doc", pkgver:"2007.dfsg.2-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"texlive-extra-utils", pkgver:"2007.dfsg.2-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"texlive-font-utils", pkgver:"2007.dfsg.2-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"texlive-lang-indic", pkgver:"2007.dfsg.2-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"texlive-metapost", pkgver:"2007.dfsg.2-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"texlive-metapost-doc", pkgver:"2007.dfsg.2-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"texlive-music", pkgver:"2007.dfsg.2-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"texlive-omega", pkgver:"2007.dfsg.2-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"texlive-xetex", pkgver:"2007.dfsg.2-7ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libkpathsea-dev", pkgver:"2009-5ubuntu0.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libkpathsea5", pkgver:"2009-5ubuntu0.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"texlive-binaries", pkgver:"2009-5ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libkpathsea-dev / libkpathsea4 / libkpathsea5 / texlive-base-bin / etc");
}
