#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-241-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20788);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/26 16:22:50 $");

  script_cve_id("CVE-2005-3352", "CVE-2005-3357");
  script_osvdb_id(21705, 22261);
  script_xref(name:"USN", value:"241-1");

  script_name(english:"Ubuntu 4.10 / 5.04 / 5.10 : apache2, apache vulnerabilities (USN-241-1)");
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
"The 'mod_imap' module (which provides support for image maps) did not
properly escape the 'referer' URL which rendered it vulnerable against
a cross-site scripting attack. A malicious web page (or HTML email)
could trick a user into visiting a site running the vulnerable
mod_imap, and employ cross-site-scripting techniques to gather
sensitive user information from that site. (CVE-2005-3352)

Hartmut Keil discovered a Denial of Service vulnerability in the SSL
module ('mod_ssl') that affects SSL-enabled virtual hosts with a
customized error page for error 400. By sending a specially crafted
request to the server, a remote attacker could crash the server. This
only affects Apache 2, and only if the 'worker' implementation
(apache2-mpm-worker) is used. (CVE-2005-3357).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache-ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-perchild");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-threadpool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-prefork-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-threaded-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache-mod-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapr0-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2006-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4\.10|5\.04|5\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10 / 5.04 / 5.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"apache", pkgver:"1.3.31-6ubuntu0.9")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache-common", pkgver:"1.3.31-6ubuntu0.9")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache-dbg", pkgver:"1.3.31-6ubuntu0.9")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache-dev", pkgver:"1.3.31-6ubuntu0.9")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache-doc", pkgver:"1.3.31-6ubuntu0.9")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache-perl", pkgver:"1.3.31-6ubuntu0.9")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache-ssl", pkgver:"1.3.31-6ubuntu0.9")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache-utils", pkgver:"1.3.31-6ubuntu0.9")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache2", pkgver:"2.0.50-12ubuntu4.10")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache2-common", pkgver:"2.0.50-12ubuntu4.10")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache2-doc", pkgver:"2.0.50-12ubuntu4.10")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache2-mpm-perchild", pkgver:"2.0.50-12ubuntu4.10")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache2-mpm-prefork", pkgver:"2.0.50-12ubuntu4.10")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache2-mpm-threadpool", pkgver:"2.0.50-12ubuntu4.10")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache2-mpm-worker", pkgver:"2.0.50-12ubuntu4.10")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache2-prefork-dev", pkgver:"2.0.50-12ubuntu4.10")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"apache2-threaded-dev", pkgver:"2.0.50-12ubuntu4.10")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libapache-mod-perl", pkgver:"1.29.0.2.0-6ubuntu0.9")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libapr0", pkgver:"2.0.50-12ubuntu4.10")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libapr0-dev", pkgver:"2.0.50-12ubuntu4.10")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache", pkgver:"1.3.33-4ubuntu2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache-common", pkgver:"1.3.33-4ubuntu2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache-dbg", pkgver:"1.3.33-4ubuntu2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache-dev", pkgver:"1.3.33-4ubuntu2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache-doc", pkgver:"1.3.33-4ubuntu2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache-perl", pkgver:"1.3.33-4ubuntu2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache-ssl", pkgver:"1.3.33-4ubuntu2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache-utils", pkgver:"1.3.33-4ubuntu2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache2", pkgver:"2.0.53-5ubuntu5.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache2-common", pkgver:"2.0.53-5ubuntu5.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache2-doc", pkgver:"2.0.53-5ubuntu5.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache2-mpm-perchild", pkgver:"2.0.53-5ubuntu5.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache2-mpm-prefork", pkgver:"2.0.53-5ubuntu5.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache2-mpm-threadpool", pkgver:"2.0.53-5ubuntu5.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache2-mpm-worker", pkgver:"2.0.53-5ubuntu5.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache2-prefork-dev", pkgver:"2.0.53-5ubuntu5.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache2-threaded-dev", pkgver:"2.0.53-5ubuntu5.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"apache2-utils", pkgver:"2.0.53-5ubuntu5.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libapache-mod-perl", pkgver:"1.29.0.3-4ubuntu2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libapr0", pkgver:"2.0.53-5ubuntu5.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libapr0-dev", pkgver:"2.0.53-5ubuntu5.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"apache", pkgver:"1.3.33-8ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"apache-common", pkgver:"1.3.33-8ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"apache-dbg", pkgver:"1.3.33-8ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"apache-dev", pkgver:"1.3.33-8ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"apache-doc", pkgver:"1.3.33-8ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"apache-perl", pkgver:"1.3.33-8ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"apache-ssl", pkgver:"1.3.33-8ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"apache-utils", pkgver:"1.3.33-8ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"apache2", pkgver:"2.0.54-5ubuntu4")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"apache2-common", pkgver:"2.0.54-5ubuntu4")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"apache2-doc", pkgver:"2.0.54-5ubuntu4")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"apache2-mpm-perchild", pkgver:"2.0.54-5ubuntu4")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"apache2-mpm-prefork", pkgver:"2.0.54-5ubuntu4")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"apache2-mpm-threadpool", pkgver:"2.0.54-5ubuntu4")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"apache2-mpm-worker", pkgver:"2.0.54-5ubuntu4")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"apache2-prefork-dev", pkgver:"2.0.54-5ubuntu4")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"apache2-threaded-dev", pkgver:"2.0.54-5ubuntu4")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"apache2-utils", pkgver:"2.0.54-5ubuntu4")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libapache-mod-perl", pkgver:"1.29.0.3-8ubuntu1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libapr0", pkgver:"2.0.54-5ubuntu4")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libapr0-dev", pkgver:"2.0.54-5ubuntu4")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache / apache-common / apache-dbg / apache-dev / apache-doc / etc");
}
