#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-651-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(37068);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/12/05 16:04:17 $");

  script_cve_id("CVE-2008-1447", "CVE-2008-2376", "CVE-2008-3443", "CVE-2008-3655", "CVE-2008-3656", "CVE-2008-3657", "CVE-2008-3790", "CVE-2008-3905");
  script_bugtraq_id(30036, 30131, 30644, 30682, 30802);
  script_xref(name:"USN", value:"651-1");
  script_xref(name:"IAVA", value:"2008-A-0045");

  script_name(english:"Ubuntu 6.06 LTS / 7.04 / 7.10 / 8.04 LTS : ruby1.8 vulnerabilities (USN-651-1)");
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
"Akira Tagoh discovered a vulnerability in Ruby which lead to an
integer overflow. If a user or automated system were tricked into
running a malicious script, an attacker could cause a denial of
service or possibly execute arbitrary code with the privileges of the
user invoking the program. (CVE-2008-2376)

Laurent Gaffie discovered that Ruby did not properly check for memory
allocation failures. If a user or automated system were tricked into
running a malicious script, an attacker could cause a denial of
service. (CVE-2008-3443)

Keita Yamaguchi discovered several safe level vulnerabilities in Ruby.
An attacker could use this to bypass intended access restrictions.
(CVE-2008-3655)

Keita Yamaguchi discovered that WEBrick in Ruby did not properly
validate paths ending with '.'. A remote attacker could send a crafted
HTTP request and cause a denial of service. (CVE-2008-3656)

Keita Yamaguchi discovered that the dl module in Ruby did not check
the taintness of inputs. An attacker could exploit this vulnerability
to bypass safe levels and execute dangerous functions. (CVE-2008-3657)

Luka Treiber and Mitja Kolsek discovered that REXML in Ruby did not
always use expansion limits when processing XML documents. If a user
or automated system were tricked into open a crafted XML file, an
attacker could cause a denial of service via CPU consumption.
(CVE-2008-3790)

Jan Lieskovsky discovered several flaws in the name resolver of Ruby.
A remote attacker could exploit this to spoof DNS entries, which could
lead to misdirected traffic. This is a different vulnerability from
CVE-2008-1447. (CVE-2008-3905).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 189, 264, 287, 399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if (ubuntu_check(osver:"6.06", pkgname:"irb1.8", pkgver:"1.8.4-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libdbm-ruby1.8", pkgver:"1.8.4-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgdbm-ruby1.8", pkgver:"1.8.4-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libopenssl-ruby1.8", pkgver:"1.8.4-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libreadline-ruby1.8", pkgver:"1.8.4-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libruby1.8", pkgver:"1.8.4-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libruby1.8-dbg", pkgver:"1.8.4-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libtcltk-ruby1.8", pkgver:"1.8.4-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"rdoc1.8", pkgver:"1.8.4-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ri1.8", pkgver:"1.8.4-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ruby1.8", pkgver:"1.8.4-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ruby1.8-dev", pkgver:"1.8.4-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ruby1.8-elisp", pkgver:"1.8.4-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ruby1.8-examples", pkgver:"1.8.4-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"irb1.8", pkgver:"1.8.5-4ubuntu2.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libdbm-ruby1.8", pkgver:"1.8.5-4ubuntu2.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libgdbm-ruby1.8", pkgver:"1.8.5-4ubuntu2.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libopenssl-ruby1.8", pkgver:"1.8.5-4ubuntu2.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libreadline-ruby1.8", pkgver:"1.8.5-4ubuntu2.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libruby1.8", pkgver:"1.8.5-4ubuntu2.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libruby1.8-dbg", pkgver:"1.8.5-4ubuntu2.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libtcltk-ruby1.8", pkgver:"1.8.5-4ubuntu2.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"rdoc1.8", pkgver:"1.8.5-4ubuntu2.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"ri1.8", pkgver:"1.8.5-4ubuntu2.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"ruby1.8", pkgver:"1.8.5-4ubuntu2.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"ruby1.8-dev", pkgver:"1.8.5-4ubuntu2.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"ruby1.8-elisp", pkgver:"1.8.5-4ubuntu2.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"ruby1.8-examples", pkgver:"1.8.5-4ubuntu2.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"irb1.8", pkgver:"1.8.6.36-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libdbm-ruby1.8", pkgver:"1.8.6.36-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libgdbm-ruby1.8", pkgver:"1.8.6.36-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libopenssl-ruby1.8", pkgver:"1.8.6.36-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libreadline-ruby1.8", pkgver:"1.8.6.36-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libruby1.8", pkgver:"1.8.6.36-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libruby1.8-dbg", pkgver:"1.8.6.36-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libtcltk-ruby1.8", pkgver:"1.8.6.36-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"rdoc1.8", pkgver:"1.8.6.36-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ri1.8", pkgver:"1.8.6.36-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ruby1.8", pkgver:"1.8.6.36-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ruby1.8-dev", pkgver:"1.8.6.36-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ruby1.8-elisp", pkgver:"1.8.6.36-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"ruby1.8-examples", pkgver:"1.8.6.36-1ubuntu3.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"irb1.8", pkgver:"1.8.6.111-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libdbm-ruby1.8", pkgver:"1.8.6.111-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libgdbm-ruby1.8", pkgver:"1.8.6.111-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libopenssl-ruby1.8", pkgver:"1.8.6.111-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libreadline-ruby1.8", pkgver:"1.8.6.111-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libruby1.8", pkgver:"1.8.6.111-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libruby1.8-dbg", pkgver:"1.8.6.111-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libtcltk-ruby1.8", pkgver:"1.8.6.111-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"rdoc1.8", pkgver:"1.8.6.111-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ri1.8", pkgver:"1.8.6.111-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ruby1.8", pkgver:"1.8.6.111-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ruby1.8-dev", pkgver:"1.8.6.111-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ruby1.8-elisp", pkgver:"1.8.6.111-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"ruby1.8-examples", pkgver:"1.8.6.111-2ubuntu1.2")) flag++;

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
