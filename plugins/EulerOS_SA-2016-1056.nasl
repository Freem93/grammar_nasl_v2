#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99818);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/02 13:34:09 $");

  script_cve_id(
    "CVE-2016-2569",
    "CVE-2016-2570",
    "CVE-2016-2571",
    "CVE-2016-2572",
    "CVE-2016-3948"
  );
  script_osvdb_id(
    134900,
    134901,
    136595
  );

  script_name(english:"EulerOS 2.0 SP1 : squid (EulerOS-SA-2016-1056)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the squid packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - Squid 3.x before 3.5.15 and 4.x before 4.0.7 does not
    properly append data to String objects, which allows
    remote servers to cause a denial of service (assertion
    failure and daemon exit) via a long string, as
    demonstrated by a crafted HTTP Vary
    header.(CVE-2016-2569)

  - The Edge Side Includes (ESI) parser in Squid 3.x before
    3.5.15 and 4.x before 4.0.7 does not check buffer
    limits during XML parsing, which allows remote HTTP
    servers to cause a denial of service (assertion failure
    and daemon exit) via a crafted XML document, related to
    esi/CustomParser.cc and
    esi/CustomParser.h.(CVE-2016-2570)

  - http.cc in Squid 3.x before 3.5.15 and 4.x before 4.0.7
    proceeds with the storage of certain data after a
    response-parsing failure, which allows remote HTTP
    servers to cause a denial of service (assertion failure
    and daemon exit) via a malformed
    response.(CVE-2016-2571)

  - http.cc in Squid 4.x before 4.0.7 relies on the HTTP
    status code after a response-parsing failure, which
    allows remote HTTP servers to cause a denial of service
    (assertion failure and daemon exit) via a malformed
    response.(CVE-2016-2572)

  - Squid 3.x before 3.5.16 and 4.x before 4.0.8 improperly
    perform bounds checking, which allows remote attackers
    to cause a denial of service via a crafted HTTP
    response, related to Vary headers.(CVE-2016-3948)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://developer.huawei.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1056
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4bfcaf5e");
  script_set_attribute(attribute:"solution", value:
"Update the affected squid packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:squid-migration-script");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(1)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1");

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

flag = 0;

pkgs = ["squid-3.5.20-2",
        "squid-migration-script-3.5.20-2"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid");
}
