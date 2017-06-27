#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2892-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88678);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/01 20:56:52 $");

  script_cve_id("CVE-2016-0742", "CVE-2016-0746", "CVE-2016-0747");
  script_osvdb_id(133663, 133664, 133665);
  script_xref(name:"USN", value:"2892-1");

  script_name(english:"Ubuntu 14.04 LTS / 15.10 : nginx vulnerabilities (USN-2892-1)");
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
"It was discovered that nginx incorrectly handled certain DNS server
responses when the resolver is enabled. A remote attacker could
possibly use this issue to cause nginx to crash, resulting in a denial
of service. (CVE-2016-0742)

It was discovered that nginx incorrectly handled CNAME response
processing when the resolver is enabled. A remote attacker could use
this issue to cause nginx to crash, resulting in a denial of service,
or possibly execute arbitrary code. (CVE-2016-0746)

It was discovered that nginx incorrectly handled CNAME resolution when
the resolver is enabled. A remote attacker could possibly use this
issue to cause nginx to consume resources, resulting in a denial of
service. (CVE-2016-0747).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nginx-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nginx-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nginx-full");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nginx-light");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nginx-naxsi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016 Canonical, Inc. / NASL script (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(14\.04|15\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 15.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"nginx-core", pkgver:"1.4.6-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"nginx-extras", pkgver:"1.4.6-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"nginx-full", pkgver:"1.4.6-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"nginx-light", pkgver:"1.4.6-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"nginx-naxsi", pkgver:"1.4.6-1ubuntu3.4")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"nginx-core", pkgver:"1.9.3-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"nginx-extras", pkgver:"1.9.3-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"nginx-full", pkgver:"1.9.3-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"nginx-light", pkgver:"1.9.3-1ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nginx-core / nginx-extras / nginx-full / nginx-light / nginx-naxsi");
}
