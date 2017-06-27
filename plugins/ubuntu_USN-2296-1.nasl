#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2296-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76706);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/08/01 15:11:53 $");

  script_cve_id("CVE-2014-1544", "CVE-2014-1547", "CVE-2014-1549", "CVE-2014-1550", "CVE-2014-1552", "CVE-2014-1555", "CVE-2014-1556", "CVE-2014-1557", "CVE-2014-1558", "CVE-2014-1559", "CVE-2014-1560");
  script_bugtraq_id(68810, 68811, 68812, 68813, 68814, 68815, 68816, 68820, 68821, 68822, 68824);
  script_osvdb_id(109409, 109410, 109411, 109412, 109428, 109429, 109430, 109431, 109432, 109433, 109434, 109437, 109438, 109439);
  script_xref(name:"USN", value:"2296-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS : thunderbird vulnerabilities (USN-2296-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Christian Holler, David Keeler and Byron Campen discovered multiple
memory safety issues in Thunderbird. If a user were tricked in to
opening a specially crafted message with scripting enabled, an
attacker could potentially exploit these to cause a denial of service
via application crash, or execute arbitrary code with the privileges
of the user invoking Thunderbird. (CVE-2014-1547)

Atte Kettunen discovered a buffer overflow when interacting with
WebAudio buffers. If a user had enabled scripting, an attacker could
potentially exploit this to cause a denial of service via application
crash or execute arbitrary code with the privileges of the user
invoking Thunderbird. (CVE-2014-1549)

Atte Kettunen discovered a use-after-free in WebAudio. If a user had
enabled scripting, an attacker could potentially exploit this to cause
a denial of service via application crash or execute arbitrary code
with the privileges of the user invoking Thunderbird. (CVE-2014-1550)

Jethro Beekman discovered a use-after-free when the FireOnStateChange
event is triggered in some circumstances. If a user had enabled
scripting, an attacker could potentially exploit this to cause a
denial of service via application crash or execute arbitrary code with
the priviliges of the user invoking Thunderbird. (CVE-2014-1555)

Patrick Cozzi discovered a crash when using the Cesium JS library to
generate WebGL content. If a user had enabled scripting, an attacker
could potentially exploit this to execute arbitrary code with the
privilges of the user invoking Thunderbird. (CVE-2014-1556)

Tyson Smith and Jesse Schwartzentruber discovered a use-after-free in
CERT_DestroyCertificate. If a user had enabled scripting, an attacker
could potentially exploit this to cause a denial of service via
application crash or execute arbitrary code with the privileges of the
user invoking Thunderbird. (CVE-2014-1544)

A crash was discovered in Skia when scaling an image, if the scaling
operation takes too long. If a user had enabled scripting, an attacker
could potentially exploit this to execute arbitrary code with the
privileges of the user invoking Thunderbird. (CVE-2014-1557)

Christian Holler discovered several issues when parsing certificates
with non-standard character encoding, resulting in the inability to
use valid SSL certificates in some circumstances. (CVE-2014-1558,
CVE-2014-1559, CVE-2014-1560)

Boris Zbarsky discovered that network redirects could cause an iframe
to escape the confinements defined by its sandbox attribute in some
circumstances. If a user had enabled scripting, an attacker could
potentially exploit this to conduct cross-site scripting attacks.
(CVE-2014-1552).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2016 Canonical, Inc. / NASL script (C) 2014-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"thunderbird", pkgver:"1:31.0+build1-0ubuntu0.12.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"thunderbird", pkgver:"1:31.0+build1-0ubuntu0.14.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
