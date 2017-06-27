#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-915-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45108);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/05 14:32:01 $");

  script_cve_id("CVE-2009-0689", "CVE-2009-2463", "CVE-2009-3072", "CVE-2009-3075", "CVE-2009-3077", "CVE-2009-3376", "CVE-2009-3983", "CVE-2010-0163");
  script_bugtraq_id(35769, 36343, 36851, 36867, 37366, 38831);
  script_osvdb_id(55603, 56230, 57972, 57976, 57978, 59389, 61091, 61101, 61186, 61187, 61188, 61189, 62402, 63263);
  script_xref(name:"USN", value:"915-1");

  script_name(english:"Ubuntu 8.04 LTS / 8.10 / 9.04 / 9.10 : thunderbird vulnerabilities (USN-915-1)");
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
"Several flaws were discovered in the JavaScript engine of Thunderbird.
If a user had JavaScript enabled and were tricked into viewing
malicious web content, a remote attacker could cause a denial of
service or possibly execute arbitrary code with the privileges of the
user invoking the program. (CVE-2009-0689, CVE-2009-2463,
CVE-2009-3075)

Josh Soref discovered that the BinHex decoder used in Thunderbird
contained a flaw. If a user were tricked into viewing malicious
content, a remote attacker could cause a denial of service or possibly
execute arbitrary code with the privileges of the user invoking the
program. (CVE-2009-3072)

It was discovered that Thunderbird did not properly manage memory when
using XUL tree elements. If a user were tricked into viewing malicious
content, a remote attacker could cause a denial of service or possibly
execute arbitrary code with the privileges of the user invoking the
program. (CVE-2009-3077)

Jesse Ruderman and Sid Stamm discovered that Thunderbird did not
properly display filenames containing right-to-left (RTL) override
characters. If a user were tricked into opening a malicious file with
a crafted filename, an attacker could exploit this to trick the user
into opening a different file than the user expected. (CVE-2009-3376)

Takehiro Takahashi discovered flaws in the NTLM implementation in
Thunderbird. If an NTLM authenticated user opened content containing
links to a malicious website, a remote attacker could send requests to
other applications, authenticated as the user. (CVE-2009-3983)

Ludovic Hirlimann discovered a flaw in the way Thunderbird indexed
certain messages with attachments. A remote attacker could send
specially crafted content and cause a denial of service or possibly
execute arbitrary code with the privileges of the user invoking the
program. (CVE-2010-0163).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 94, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mozilla-thunderbird-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird-gnome-support");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/19");
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
if (! ereg(pattern:"^(8\.04|8\.10|9\.04|9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 8.10 / 9.04 / 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"mozilla-thunderbird", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"mozilla-thunderbird-dev", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"thunderbird", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"thunderbird-dev", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"thunderbird-gnome-support", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.8.04.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"mozilla-thunderbird", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"mozilla-thunderbird-dev", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"thunderbird", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"thunderbird-dev", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"thunderbird-gnome-support", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.8.10.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mozilla-thunderbird", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"mozilla-thunderbird-dev", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"thunderbird", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"thunderbird-dev", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"thunderbird-gnome-support", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.9.04.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"mozilla-thunderbird", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"mozilla-thunderbird-dev", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"thunderbird", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"thunderbird-dev", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.9.10.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"thunderbird-gnome-support", pkgver:"2.0.0.24+build1+nobinonly-0ubuntu0.9.10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mozilla-thunderbird / mozilla-thunderbird-dev / thunderbird / etc");
}
