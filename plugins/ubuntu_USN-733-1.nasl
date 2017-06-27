#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-733-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36746);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/27 14:37:18 $");

  script_cve_id("CVE-2009-0587");
  script_bugtraq_id(34100);
  script_xref(name:"USN", value:"733-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.10 : evolution-data-server vulnerability (USN-733-1)");
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
"It was discovered that the Base64 encoding functions in
evolution-data-server did not properly handle large strings. If a user
were tricked into opening a specially crafted image file, or tricked
into connecting to a malicious server, an attacker could possibly
execute arbitrary code with user privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:evolution-data-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:evolution-data-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:evolution-data-server-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:evolution-data-server-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcamel1.2-10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcamel1.2-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcamel1.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libebook1.2-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libebook1.2-9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libebook1.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecal1.2-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecal1.2-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecal1.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libedata-book1.2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libedata-book1.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libedata-cal1.2-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libedata-cal1.2-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libedata-cal1.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libedataserver1.2-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libedataserver1.2-9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libedataserver1.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libedataserverui1.2-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libedataserverui1.2-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libedataserverui1.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libegroupwise1.2-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libegroupwise1.2-9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libegroupwise1.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libexchange-storage1.2-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libexchange-storage1.2-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libexchange-storage1.2-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|7\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"evolution-data-server", pkgver:"1.6.1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"evolution-data-server-dbg", pkgver:"1.6.1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"evolution-data-server-dev", pkgver:"1.6.1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcamel1.2-8", pkgver:"1.6.1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcamel1.2-dev", pkgver:"1.6.1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libebook1.2-5", pkgver:"1.6.1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libebook1.2-dev", pkgver:"1.6.1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libecal1.2-3", pkgver:"1.6.1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libecal1.2-dev", pkgver:"1.6.1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libedata-book1.2-2", pkgver:"1.6.1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libedata-book1.2-dev", pkgver:"1.6.1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libedata-cal1.2-1", pkgver:"1.6.1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libedata-cal1.2-dev", pkgver:"1.6.1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libedataserver1.2-7", pkgver:"1.6.1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libedataserver1.2-dev", pkgver:"1.6.1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libedataserverui1.2-6", pkgver:"1.6.1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libedataserverui1.2-dev", pkgver:"1.6.1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libegroupwise1.2-9", pkgver:"1.6.1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libegroupwise1.2-dev", pkgver:"1.6.1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libexchange-storage1.2-1", pkgver:"1.6.1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libexchange-storage1.2-dev", pkgver:"1.6.1-0ubuntu7.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"evolution-data-server", pkgver:"1.12.1-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"evolution-data-server-common", pkgver:"1.12.1-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"evolution-data-server-dbg", pkgver:"1.12.1-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"evolution-data-server-dev", pkgver:"1.12.1-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcamel1.2-10", pkgver:"1.12.1-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcamel1.2-dev", pkgver:"1.12.1-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libebook1.2-9", pkgver:"1.12.1-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libebook1.2-dev", pkgver:"1.12.1-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libecal1.2-7", pkgver:"1.12.1-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libecal1.2-dev", pkgver:"1.12.1-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libedata-book1.2-2", pkgver:"1.12.1-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libedata-book1.2-dev", pkgver:"1.12.1-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libedata-cal1.2-6", pkgver:"1.12.1-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libedata-cal1.2-dev", pkgver:"1.12.1-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libedataserver1.2-9", pkgver:"1.12.1-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libedataserver1.2-dev", pkgver:"1.12.1-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libedataserverui1.2-8", pkgver:"1.12.1-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libedataserverui1.2-dev", pkgver:"1.12.1-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libegroupwise1.2-13", pkgver:"1.12.1-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libegroupwise1.2-dev", pkgver:"1.12.1-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libexchange-storage1.2-3", pkgver:"1.12.1-0ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libexchange-storage1.2-dev", pkgver:"1.12.1-0ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "evolution-data-server / evolution-data-server-common / etc");
}
