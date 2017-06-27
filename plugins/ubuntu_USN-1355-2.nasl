#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1355-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57845);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/25 16:11:45 $");

  script_cve_id("CVE-2011-3659", "CVE-2012-0442", "CVE-2012-0443", "CVE-2012-0444", "CVE-2012-0445", "CVE-2012-0446", "CVE-2012-0447", "CVE-2012-0449", "CVE-2012-0450");
  script_osvdb_id(78733, 78734, 78735, 78736, 78737, 78738, 78739, 78740, 78741);
  script_xref(name:"USN", value:"1355-2");

  script_name(english:"Ubuntu 10.04 LTS / 10.10 / 11.04 / 11.10 : mozvoikko update (USN-1355-2)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-1355-1 fixed vulnerabilities in Firefox. This update provides an
updated Mozvoikko package for use with the latest Firefox.

It was discovered that if a user chose to export their Firefox Sync
key the 'Firefox Recovery Key.html' file is saved with incorrect
permissions, making the file contents potentially readable by other
users. (CVE-2012-0450)

Nicolas Gregoire and Aki Helin discovered that when
processing a malformed embedded XSLT stylesheet, Firefox can
crash due to memory corruption. If the user were tricked
into opening a specially crafted page, an attacker could
exploit this to cause a denial of service via application
crash, or potentially execute code with the privileges of
the user invoking Firefox. (CVE-2012-0449)

It was discovered that memory corruption could occur during
the decoding of Ogg Vorbis files. If the user were tricked
into opening a specially crafted file, an attacker could
exploit this to cause a denial of service via application
crash, or potentially execute code with the privileges of
the user invoking Firefox. (CVE-2012-0444)

Tim Abraldes discovered that when encoding certain images
types the resulting data was always a fixed size. There is
the possibility of sensitive data from uninitialized memory
being appended to these images. (CVE-2012-0447)

It was discovered that Firefox did not properly perform
XPConnect security checks. An attacker could exploit this to
conduct cross-site scripting (XSS) attacks through web pages
and Firefox extensions. With cross-site scripting
vulnerabilities, if a user were tricked into viewing a
specially crafted page, a remote attacker could exploit this
to modify the contents, or steal confidential data, within
the same domain. (CVE-2012-0446)

It was discovered that Firefox did not properly handle node
removal in the DOM. If the user were tricked into opening a
specially crafted page, an attacker could exploit this to
cause a denial of service via application crash, or
potentially execute code with the privileges of the user
invoking Firefox. (CVE-2011-3659)

Alex Dvorov discovered that Firefox did not properly handle
sub-frames in form submissions. An attacker could exploit
this to conduct phishing attacks using HTML5 frames.
(CVE-2012-0445)

Ben Hawkes, Christian Holler, Honza Bombas, Jason Orendorff,
Jesse Ruderman, Jan Odvarko, Peter Van Der Beken, Bob Clary,
and Bill McCloskey discovered memory safety issues affecting
Firefox. If the user were tricked into opening a specially
crafted page, an attacker could exploit these to cause a
denial of service via application crash, or potentially
execute code with the privileges of the user invoking
Firefox. (CVE-2012-0442, CVE-2012-0443).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xul-ext-mozvoikko package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox 8/9 AttributeChildRemoved() Use-After-Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xul-ext-mozvoikko");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2012-2016 Canonical, Inc. / NASL script (C) 2012-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04|10\.10|11\.04|11\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 10.10 / 11.04 / 11.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"xul-ext-mozvoikko", pkgver:"2.0.1-0ubuntu0.10.04.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"xul-ext-mozvoikko", pkgver:"2.0.1-0ubuntu0.10.10.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"xul-ext-mozvoikko", pkgver:"2.0.1-0ubuntu0.11.04.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"xul-ext-mozvoikko", pkgver:"2.0.1-0ubuntu0.11.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xul-ext-mozvoikko");
}
