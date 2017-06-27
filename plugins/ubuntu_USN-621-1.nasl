#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-621-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33390);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2008-2662", "CVE-2008-2663", "CVE-2008-2664", "CVE-2008-2725", "CVE-2008-2726");
  script_bugtraq_id(29903);
  script_osvdb_id(46553);
  script_xref(name:"USN", value:"621-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.04 / 7.10 / 8.04 LTS : ruby1.8 vulnerabilities (USN-621-1)");
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
"Drew Yao discovered several vulnerabilities in Ruby which lead to
integer overflows. If a user or automated system were tricked into
running a malicious script, an attacker could cause a denial of
service or execute arbitrary code with the privileges of the user
invoking the program. (CVE-2008-2662, CVE-2008-2663, CVE-2008-2725,
CVE-2008-2726)

Drew Yao discovered that Ruby did not sanitize its input when using
ALLOCA. If a user or automated system were tricked into running a
malicious script, an attacker could cause a denial of service via
memory corruption. (CVE-2008-2664).

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
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:irb1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdbm-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgdbm-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopenssl-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreadline-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libruby1.8-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtcltk-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rdoc1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ri1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.8-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.8-elisp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.8-examples");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2008-2016 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"6.06", pkgname:"irb1.8", pkgver:"1.8.4-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libdbm-ruby1.8", pkgver:"1.8.4-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgdbm-ruby1.8", pkgver:"1.8.4-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libopenssl-ruby1.8", pkgver:"1.8.4-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libreadline-ruby1.8", pkgver:"1.8.4-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libruby1.8", pkgver:"1.8.4-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libruby1.8-dbg", pkgver:"1.8.4-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libtcltk-ruby1.8", pkgver:"1.8.4-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"rdoc1.8", pkgver:"1.8.4-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ri1.8", pkgver:"1.8.4-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ruby1.8", pkgver:"1.8.4-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ruby1.8-dev", pkgver:"1.8.4-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ruby1.8-elisp", pkgver:"1.8.4-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ruby1.8-examples", pkgver:"1.8.4-1ubuntu1.5")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"irb1.8", pkgver:"1.8.5-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libdbm-ruby1.8", pkgver:"1.8.5-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libgdbm-ruby1.8", pkgver:"1.8.5-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libopenssl-ruby1.8", pkgver:"1.8.5-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libreadline-ruby1.8", pkgver:"1.8.5-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libruby1.8", pkgver:"1.8.5-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libruby1.8-dbg", pkgver:"1.8.5-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libtcltk-ruby1.8", pkgver:"1.8.5-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"rdoc1.8", pkgver:"1.8.5-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"ri1.8", pkgver:"1.8.5-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"ruby1.8", pkgver:"1.8.5-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"ruby1.8-dev", pkgver:"1.8.5-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"ruby1.8-elisp", pkgver:"1.8.5-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"ruby1.8-examples", pkgver:"1.8.5-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"irb1.8", pkgver:"1.8.6.36-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libdbm-ruby1.8", pkgver:"1.8.6.36-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libgdbm-ruby1.8", pkgver:"1.8.6.36-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libopenssl-ruby1.8", pkgver:"1.8.6.36-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libreadline-ruby1.8", pkgver:"1.8.6.36-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libruby1.8", pkgver:"1.8.6.36-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libruby1.8-dbg", pkgver:"1.8.6.36-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libtcltk-ruby1.8", pkgver:"1.8.6.36-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"rdoc1.8", pkgver:"1.8.6.36-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ri1.8", pkgver:"1.8.6.36-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ruby1.8", pkgver:"1.8.6.36-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ruby1.8-dev", pkgver:"1.8.6.36-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ruby1.8-elisp", pkgver:"1.8.6.36-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ruby1.8-examples", pkgver:"1.8.6.36-1ubuntu3.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"irb1.8", pkgver:"1.8.6.111-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libdbm-ruby1.8", pkgver:"1.8.6.111-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libgdbm-ruby1.8", pkgver:"1.8.6.111-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libopenssl-ruby1.8", pkgver:"1.8.6.111-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libreadline-ruby1.8", pkgver:"1.8.6.111-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libruby1.8", pkgver:"1.8.6.111-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libruby1.8-dbg", pkgver:"1.8.6.111-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libtcltk-ruby1.8", pkgver:"1.8.6.111-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"rdoc1.8", pkgver:"1.8.6.111-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ri1.8", pkgver:"1.8.6.111-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ruby1.8", pkgver:"1.8.6.111-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ruby1.8-dev", pkgver:"1.8.6.111-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ruby1.8-elisp", pkgver:"1.8.6.111-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ruby1.8-examples", pkgver:"1.8.6.111-2ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "irb1.8 / libdbm-ruby1.8 / libgdbm-ruby1.8 / libopenssl-ruby1.8 / etc");
}
