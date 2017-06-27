#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-596-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31704);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:29:19 $");

  script_cve_id("CVE-2007-5162", "CVE-2007-5770");
  script_osvdb_id(40773);
  script_xref(name:"USN", value:"596-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 / 7.10 : ruby1.8 vulnerabilities (USN-596-1)");
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
"Chris Clark discovered that Ruby's HTTPS module did not check for
commonName mismatches early enough during SSL negotiation. If a remote
attacker were able to perform man-in-the-middle attacks, this flaw
could be exploited to view sensitive information in HTTPS requests
coming from Ruby applications. (CVE-2007-5162)

It was discovered that Ruby's FTPTLS, telnets, and IMAPS modules did
not check the commonName when performing SSL certificate checks. If a
remote attacker were able to perform man-in-the-middle attacks, this
flaw could be exploited to eavesdrop on encrypted communications from
Ruby applications using these protocols. (CVE-2007-5770).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cwe_id(287);

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/28");
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
if (! ereg(pattern:"^(6\.06|6\.10|7\.04|7\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 6.10 / 7.04 / 7.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"irb1.8", pkgver:"1.8.4-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libdbm-ruby1.8", pkgver:"1.8.4-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgdbm-ruby1.8", pkgver:"1.8.4-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libopenssl-ruby1.8", pkgver:"1.8.4-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libreadline-ruby1.8", pkgver:"1.8.4-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libruby1.8", pkgver:"1.8.4-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libruby1.8-dbg", pkgver:"1.8.4-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libtcltk-ruby1.8", pkgver:"1.8.4-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"rdoc1.8", pkgver:"1.8.4-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ri1.8", pkgver:"1.8.4-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ruby1.8", pkgver:"1.8.4-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ruby1.8-dev", pkgver:"1.8.4-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ruby1.8-elisp", pkgver:"1.8.4-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ruby1.8-examples", pkgver:"1.8.4-1ubuntu1.4")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"irb1.8", pkgver:"1.8.4-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libdbm-ruby1.8", pkgver:"1.8.4-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libgdbm-ruby1.8", pkgver:"1.8.4-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libopenssl-ruby1.8", pkgver:"1.8.4-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libreadline-ruby1.8", pkgver:"1.8.4-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libruby1.8", pkgver:"1.8.4-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libruby1.8-dbg", pkgver:"1.8.4-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libtcltk-ruby1.8", pkgver:"1.8.4-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"rdoc1.8", pkgver:"1.8.4-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"ri1.8", pkgver:"1.8.4-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"ruby1.8", pkgver:"1.8.4-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"ruby1.8-dev", pkgver:"1.8.4-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"ruby1.8-elisp", pkgver:"1.8.4-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"ruby1.8-examples", pkgver:"1.8.4-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"irb1.8", pkgver:"1.8.5-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libdbm-ruby1.8", pkgver:"1.8.5-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libgdbm-ruby1.8", pkgver:"1.8.5-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libopenssl-ruby1.8", pkgver:"1.8.5-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libreadline-ruby1.8", pkgver:"1.8.5-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libruby1.8", pkgver:"1.8.5-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libruby1.8-dbg", pkgver:"1.8.5-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libtcltk-ruby1.8", pkgver:"1.8.5-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"rdoc1.8", pkgver:"1.8.5-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"ri1.8", pkgver:"1.8.5-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"ruby1.8", pkgver:"1.8.5-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"ruby1.8-dev", pkgver:"1.8.5-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"ruby1.8-elisp", pkgver:"1.8.5-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"ruby1.8-examples", pkgver:"1.8.5-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"irb1.8", pkgver:"1.8.6.36-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libdbm-ruby1.8", pkgver:"1.8.6.36-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libgdbm-ruby1.8", pkgver:"1.8.6.36-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libopenssl-ruby1.8", pkgver:"1.8.6.36-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libreadline-ruby1.8", pkgver:"1.8.6.36-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libruby1.8", pkgver:"1.8.6.36-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libruby1.8-dbg", pkgver:"1.8.6.36-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libtcltk-ruby1.8", pkgver:"1.8.6.36-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"rdoc1.8", pkgver:"1.8.6.36-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ri1.8", pkgver:"1.8.6.36-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ruby1.8", pkgver:"1.8.6.36-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ruby1.8-dev", pkgver:"1.8.6.36-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ruby1.8-elisp", pkgver:"1.8.6.36-1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ruby1.8-examples", pkgver:"1.8.6.36-1ubuntu3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "irb1.8 / libdbm-ruby1.8 / libgdbm-ruby1.8 / libopenssl-ruby1.8 / etc");
}
