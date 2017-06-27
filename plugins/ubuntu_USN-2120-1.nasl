#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2120-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72682);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/26 16:22:49 $");

  script_cve_id("CVE-2014-0060", "CVE-2014-0061", "CVE-2014-0062", "CVE-2014-0063", "CVE-2014-0064", "CVE-2014-0065", "CVE-2014-0066");
  script_bugtraq_id(65719, 65723, 65724, 65725, 65727, 65728, 65731);
  script_osvdb_id(103544, 103545, 103546, 103547, 103548, 103549, 103551);
  script_xref(name:"USN", value:"2120-1");

  script_name(english:"Ubuntu 10.04 LTS / 12.04 LTS / 12.10 / 13.10 : postgresql-8.4, postgresql-9.1 vulnerabilities (USN-2120-1)");
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
"Noah Misch and Jonas Sundman discovered that PostgreSQL did not
correctly enforce ADMIN OPTION restrictions. An authenticated attacker
could use this issue to possibly revoke access from others, contrary
to expected permissions. (CVE-2014-0060)

Andres Freund discovered that PostgreSQL incorrectly handled validator
functions. An authenticated attacker could possibly use this issue to
escalate their privileges. (CVE-2014-0061)

Andres Freund discovered that PostgreSQL incorrectly handled
concurrent CREATE INDEX statements. An authenticated attacker could
possibly use this issue to obtain access to restricted data, bypassing
intended privileges. (CVE-2014-0062)

Daniel Schussler discovered that PostgreSQL incorrectly handled
datetime input. An authenticated attacker could possibly use this
issue to cause PostgreSQL to crash, resulting in a denial of service,
or possibly execute arbitrary code. (CVE-2014-0063)

It was discovered that PostgreSQL incorrectly handled certain size
calculations. An authenticated attacker could possibly use this issue
to cause PostgreSQL to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2014-0064)

Peter Eisentraut and Jozef Mlich discovered that PostgreSQL
incorrectly handled certain buffer sizes. An authenticated attacker
could possibly use this issue to cause PostgreSQL to crash, resulting
in a denial of service, or possibly execute arbitrary code.
(CVE-2014-0065)

Honza Horak discovered that PostgreSQL incorrectly used the crypt()
library function. This issue could possibly cause PostgreSQL to crash,
resulting in a denial of service (CVE-2014-0066).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postgresql-8.4 and / or postgresql-9.1 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-8.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:postgresql-9.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/25");
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
if (! ereg(pattern:"^(10\.04|12\.04|12\.10|13\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 12.04 / 12.10 / 13.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"postgresql-8.4", pkgver:"8.4.20-0ubuntu010.04")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"postgresql-9.1", pkgver:"9.1.12-0ubuntu0.12.04")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"postgresql-9.1", pkgver:"9.1.12-0ubuntu0.12.10")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"postgresql-9.1", pkgver:"9.1.12-0ubuntu0.13.10")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql-8.4 / postgresql-9.1");
}
