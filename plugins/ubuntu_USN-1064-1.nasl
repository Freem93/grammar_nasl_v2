#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1064-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51996);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/08/29 13:57:37 $");

  script_cve_id("CVE-2011-0014");
  script_bugtraq_id(46264);
  script_osvdb_id(70847);
  script_xref(name:"USN", value:"1064-1");

  script_name(english:"Ubuntu 10.04 LTS / 10.10 : openssl vulnerability (USN-1064-1)");
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
"Neel Mehta discovered that incorrectly formatted ClientHello handshake
messages could cause OpenSSL to parse past the end of the message.
This could allow a remote attacker to cause a crash and denial of
service by triggering invalid memory accesses.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl0.9.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl0.9.8-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssl-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2016 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04|10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"libssl-dev", pkgver:"0.9.8k-7ubuntu8.6")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libssl0.9.8", pkgver:"0.9.8k-7ubuntu8.6")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libssl0.9.8-dbg", pkgver:"0.9.8k-7ubuntu8.6")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openssl", pkgver:"0.9.8k-7ubuntu8.6")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"openssl-doc", pkgver:"0.9.8k-7ubuntu8.6")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libssl-dev", pkgver:"0.9.8o-1ubuntu4.4")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libssl0.9.8", pkgver:"0.9.8o-1ubuntu4.4")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libssl0.9.8-dbg", pkgver:"0.9.8o-1ubuntu4.4")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openssl", pkgver:"0.9.8o-1ubuntu4.4")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"openssl-doc", pkgver:"0.9.8o-1ubuntu4.4")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libssl-dev / libssl0.9.8 / libssl0.9.8-dbg / openssl / openssl-doc");
}
