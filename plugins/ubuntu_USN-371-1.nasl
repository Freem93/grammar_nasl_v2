#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-371-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27952);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:21:18 $");

  script_cve_id("CVE-2004-0983", "CVE-2006-5467");
  script_bugtraq_id(20777);
  script_osvdb_id(11534, 34237);
  script_xref(name:"USN", value:"371-1");

  script_name(english:"Ubuntu 5.04 / 5.10 / 6.06 LTS / 6.10 : ruby1.8 vulnerability (USN-371-1)");
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
"An error was found in Ruby's CGI library that did not correctly check
for the end of multipart MIME requests. Using a crafted HTTP request,
a remote user could cause a denial of service, where Ruby CGI
applications would end up in a loop, monopolizing a CPU.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:irb1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbigdecimal-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurses-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdbm-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdl-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdrb-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liberb-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgdbm-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libiconv-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopenssl-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpty-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libracc-runtime-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreadline-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librexml-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libruby1.8-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsdbm-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsoap-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libstrscan-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsyslog-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtcltk-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtest-unit-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtk-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwebrick-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxmlrpc-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libyaml-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libzlib-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rdoc1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ri1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.8-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.8-elisp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.8-examples");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2006-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5\.04|5\.10|6\.06|6\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.04 / 5.10 / 6.06 / 6.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.04", pkgname:"irb1.8", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libbigdecimal-ruby1.8", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libcurses-ruby1.8", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libdbm-ruby1.8", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libdl-ruby1.8", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libdrb-ruby1.8", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"liberb-ruby1.8", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libgdbm-ruby1.8", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libiconv-ruby1.8", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libopenssl-ruby1.8", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libpty-ruby1.8", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libracc-runtime-ruby1.8", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libreadline-ruby1.8", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"librexml-ruby1.8", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libruby1.8", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libruby1.8-dbg", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libsdbm-ruby1.8", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libsoap-ruby1.8", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libstrscan-ruby1.8", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libsyslog-ruby1.8", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libtcltk-ruby1.8", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libtest-unit-ruby1.8", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libtk-ruby1.8", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libwebrick-ruby1.8", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxmlrpc-ruby1.8", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libyaml-ruby1.8", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libzlib-ruby1.8", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"rdoc1.8", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"ri1.8", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"ruby1.8", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"ruby1.8-dev", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"ruby1.8-elisp", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"ruby1.8-examples", pkgver:"1.8.1+1.8.2pre4-1ubuntu0.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"irb1.8", pkgver:"1.8.2-9ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libdbm-ruby1.8", pkgver:"1.8.2-9ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libgdbm-ruby1.8", pkgver:"1.8.2-9ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libopenssl-ruby1.8", pkgver:"1.8.2-9ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libreadline-ruby1.8", pkgver:"1.8.2-9ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libruby1.8", pkgver:"1.8.2-9ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libruby1.8-dbg", pkgver:"1.8.2-9ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libtcltk-ruby1.8", pkgver:"1.8.2-9ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"rdoc1.8", pkgver:"1.8.2-9ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"ri1.8", pkgver:"1.8.2-9ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"ruby1.8", pkgver:"1.8.2-9ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"ruby1.8-dev", pkgver:"1.8.2-9ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"ruby1.8-elisp", pkgver:"1.8.2-9ubuntu1.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"ruby1.8-examples", pkgver:"1.8.2-9ubuntu1.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"irb1.8", pkgver:"1.8.4-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libdbm-ruby1.8", pkgver:"1.8.4-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgdbm-ruby1.8", pkgver:"1.8.4-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libopenssl-ruby1.8", pkgver:"1.8.4-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libreadline-ruby1.8", pkgver:"1.8.4-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libruby1.8", pkgver:"1.8.4-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libruby1.8-dbg", pkgver:"1.8.4-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libtcltk-ruby1.8", pkgver:"1.8.4-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"rdoc1.8", pkgver:"1.8.4-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ri1.8", pkgver:"1.8.4-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ruby1.8", pkgver:"1.8.4-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ruby1.8-dev", pkgver:"1.8.4-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ruby1.8-elisp", pkgver:"1.8.4-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"ruby1.8-examples", pkgver:"1.8.4-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"irb1.8", pkgver:"1.8.4-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libdbm-ruby1.8", pkgver:"1.8.4-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libgdbm-ruby1.8", pkgver:"1.8.4-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libopenssl-ruby1.8", pkgver:"1.8.4-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libreadline-ruby1.8", pkgver:"1.8.4-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libruby1.8", pkgver:"1.8.4-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libruby1.8-dbg", pkgver:"1.8.4-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libtcltk-ruby1.8", pkgver:"1.8.4-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"rdoc1.8", pkgver:"1.8.4-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"ri1.8", pkgver:"1.8.4-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"ruby1.8", pkgver:"1.8.4-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"ruby1.8-dev", pkgver:"1.8.4-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"ruby1.8-elisp", pkgver:"1.8.4-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"ruby1.8-examples", pkgver:"1.8.4-5ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "irb1.8 / libbigdecimal-ruby1.8 / libcurses-ruby1.8 / libdbm-ruby1.8 / etc");
}
