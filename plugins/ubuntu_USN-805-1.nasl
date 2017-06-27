#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-805-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40329);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/01 21:21:52 $");

  script_cve_id("CVE-2009-0642", "CVE-2009-1904");
  script_bugtraq_id(35278);
  script_osvdb_id(52194, 55031);
  script_xref(name:"USN", value:"805-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 / 9.04 : ruby1.8, ruby1.9 vulnerabilities (USN-805-1)");
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
"It was discovered that Ruby did not properly validate certificates. An
attacker could exploit this and present invalid or revoked X.509
certificates. (CVE-2009-0642)

It was discovered that Ruby did not properly handle string arguments
that represent large numbers. An attacker could exploit this and cause
a denial of service. (CVE-2009-1904).

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
  script_cwe_id(189, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:irb1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:irb1.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdbm-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdbm-ruby1.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgdbm-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgdbm-ruby1.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopenssl-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopenssl-ruby1.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreadline-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreadline-ruby1.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libruby1.8-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libruby1.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libruby1.9-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtcltk-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtcltk-ruby1.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rdoc1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rdoc1.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ri1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ri1.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.8-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.8-elisp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.8-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.9-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.9-elisp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.9-examples");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");
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

if (ubuntu_check(osver:"6.06", pkgname:"irb1.8", pkgver:"1.8.4-1ubuntu1.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libdbm-ruby1.8", pkgver:"1.8.4-1ubuntu1.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgdbm-ruby1.8", pkgver:"1.8.4-1ubuntu1.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libopenssl-ruby1.8", pkgver:"1.8.4-1ubuntu1.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libreadline-ruby1.8", pkgver:"1.8.4-1ubuntu1.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libruby1.8", pkgver:"1.8.4-1ubuntu1.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libruby1.8-dbg", pkgver:"1.8.4-1ubuntu1.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libtcltk-ruby1.8", pkgver:"1.8.4-1ubuntu1.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"rdoc1.8", pkgver:"1.8.4-1ubuntu1.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ri1.8", pkgver:"1.8.4-1ubuntu1.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ruby1.8", pkgver:"1.8.4-1ubuntu1.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ruby1.8-dev", pkgver:"1.8.4-1ubuntu1.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ruby1.8-elisp", pkgver:"1.8.4-1ubuntu1.7")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ruby1.8-examples", pkgver:"1.8.4-1ubuntu1.7")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"irb1.8", pkgver:"1.8.6.111-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libdbm-ruby1.8", pkgver:"1.8.6.111-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libgdbm-ruby1.8", pkgver:"1.8.6.111-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libopenssl-ruby1.8", pkgver:"1.8.6.111-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libreadline-ruby1.8", pkgver:"1.8.6.111-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libruby1.8", pkgver:"1.8.6.111-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libruby1.8-dbg", pkgver:"1.8.6.111-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libtcltk-ruby1.8", pkgver:"1.8.6.111-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"rdoc1.8", pkgver:"1.8.6.111-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ri1.8", pkgver:"1.8.6.111-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ruby1.8", pkgver:"1.8.6.111-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ruby1.8-dev", pkgver:"1.8.6.111-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ruby1.8-elisp", pkgver:"1.8.6.111-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ruby1.8-examples", pkgver:"1.8.6.111-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"irb1.8", pkgver:"1.8.7.72-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"irb1.9", pkgver:"1.9.0.2-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libdbm-ruby1.8", pkgver:"1.8.7.72-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libdbm-ruby1.9", pkgver:"1.9.0.2-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libgdbm-ruby1.8", pkgver:"1.8.7.72-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libgdbm-ruby1.9", pkgver:"1.9.0.2-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libopenssl-ruby1.8", pkgver:"1.8.7.72-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libopenssl-ruby1.9", pkgver:"1.9.0.2-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libreadline-ruby1.8", pkgver:"1.8.7.72-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libreadline-ruby1.9", pkgver:"1.9.0.2-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libruby1.8", pkgver:"1.8.7.72-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libruby1.8-dbg", pkgver:"1.8.7.72-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libruby1.9", pkgver:"1.9.0.2-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libruby1.9-dbg", pkgver:"1.9.0.2-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libtcltk-ruby1.8", pkgver:"1.8.7.72-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libtcltk-ruby1.9", pkgver:"1.9.0.2-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"rdoc1.8", pkgver:"1.8.7.72-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"rdoc1.9", pkgver:"1.9.0.2-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ri1.8", pkgver:"1.8.7.72-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ri1.9", pkgver:"1.9.0.2-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ruby1.8", pkgver:"1.8.7.72-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ruby1.8-dev", pkgver:"1.8.7.72-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ruby1.8-elisp", pkgver:"1.8.7.72-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ruby1.8-examples", pkgver:"1.8.7.72-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ruby1.9", pkgver:"1.9.0.2-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ruby1.9-dev", pkgver:"1.9.0.2-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ruby1.9-elisp", pkgver:"1.9.0.2-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"ruby1.9-examples", pkgver:"1.9.0.2-7ubuntu1.2")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"irb1.8", pkgver:"1.8.7.72-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"irb1.9", pkgver:"1.9.0.2-9ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libdbm-ruby1.8", pkgver:"1.8.7.72-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libdbm-ruby1.9", pkgver:"1.9.0.2-9ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libgdbm-ruby1.8", pkgver:"1.8.7.72-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libgdbm-ruby1.9", pkgver:"1.9.0.2-9ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libopenssl-ruby1.8", pkgver:"1.8.7.72-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libopenssl-ruby1.9", pkgver:"1.9.0.2-9ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libreadline-ruby1.8", pkgver:"1.8.7.72-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libreadline-ruby1.9", pkgver:"1.9.0.2-9ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libruby1.8", pkgver:"1.8.7.72-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libruby1.8-dbg", pkgver:"1.8.7.72-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libruby1.9", pkgver:"1.9.0.2-9ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libruby1.9-dbg", pkgver:"1.9.0.2-9ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libtcltk-ruby1.8", pkgver:"1.8.7.72-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libtcltk-ruby1.9", pkgver:"1.9.0.2-9ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"rdoc1.8", pkgver:"1.8.7.72-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"rdoc1.9", pkgver:"1.9.0.2-9ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ri1.8", pkgver:"1.8.7.72-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ri1.9", pkgver:"1.9.0.2-9ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ruby1.8", pkgver:"1.8.7.72-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ruby1.8-dev", pkgver:"1.8.7.72-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ruby1.8-elisp", pkgver:"1.8.7.72-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ruby1.8-examples", pkgver:"1.8.7.72-3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ruby1.9", pkgver:"1.9.0.2-9ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ruby1.9-dev", pkgver:"1.9.0.2-9ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ruby1.9-elisp", pkgver:"1.9.0.2-9ubuntu1.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"ruby1.9-examples", pkgver:"1.9.0.2-9ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "irb1.8 / irb1.9 / libdbm-ruby1.8 / libdbm-ruby1.9 / libgdbm-ruby1.8 / etc");
}
