#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-899-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44594);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/01 21:21:53 $");

  script_cve_id("CVE-2009-2693", "CVE-2009-2901", "CVE-2009-2902");
  script_bugtraq_id(37942, 37944, 37945);
  script_xref(name:"USN", value:"899-1");

  script_name(english:"Ubuntu 8.10 / 9.04 / 9.10 : tomcat6 vulnerabilities (USN-899-1)");
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
"It was discovered that Tomcat did not correctly validate WAR filenames
or paths when deploying. A remote attacker could send a specially
crafted WAR file to be deployed and cause arbitrary files and
directories to be created, overwritten, or deleted.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libservlet2.5-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libservlet2.5-java-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtomcat6-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat6-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat6-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat6-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat6-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat6-user");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/12");
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
if (! ereg(pattern:"^(8\.10|9\.04|9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.10 / 9.04 / 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.10", pkgname:"libservlet2.5-java", pkgver:"6.0.18-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libtomcat6-java", pkgver:"6.0.18-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"tomcat6", pkgver:"6.0.18-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"tomcat6-admin", pkgver:"6.0.18-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"tomcat6-common", pkgver:"6.0.18-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"tomcat6-docs", pkgver:"6.0.18-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"tomcat6-examples", pkgver:"6.0.18-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"tomcat6-user", pkgver:"6.0.18-0ubuntu3.3")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libservlet2.5-java", pkgver:"6.0.18-0ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libservlet2.5-java-doc", pkgver:"6.0.18-0ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libtomcat6-java", pkgver:"6.0.18-0ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"tomcat6", pkgver:"6.0.18-0ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"tomcat6-admin", pkgver:"6.0.18-0ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"tomcat6-common", pkgver:"6.0.18-0ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"tomcat6-docs", pkgver:"6.0.18-0ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"tomcat6-examples", pkgver:"6.0.18-0ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"tomcat6-user", pkgver:"6.0.18-0ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libservlet2.5-java", pkgver:"6.0.20-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libservlet2.5-java-doc", pkgver:"6.0.20-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libtomcat6-java", pkgver:"6.0.20-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"tomcat6", pkgver:"6.0.20-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"tomcat6-admin", pkgver:"6.0.20-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"tomcat6-common", pkgver:"6.0.20-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"tomcat6-docs", pkgver:"6.0.20-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"tomcat6-examples", pkgver:"6.0.20-2ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"tomcat6-user", pkgver:"6.0.20-2ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libservlet2.5-java / libservlet2.5-java-doc / libtomcat6-java / etc");
}
