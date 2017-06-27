#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99820);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/19 14:17:02 $");

  script_cve_id(
    "CVE-2016-5423",
    "CVE-2016-5424"
  );
  script_osvdb_id(
    142811,
    142826
  );

  script_name(english:"EulerOS 2.0 SP1 : postgresql (EulerOS-SA-2016-1058)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the postgresql packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A flaw was found in the way PostgreSQL server handled
    certain SQL statements containing CASE/WHEN commands. A
    remote, authenticated attacker could use a specially
    crafted SQL statement to cause PostgreSQL to crash or
    disclose a few bytes of server memory or possibly
    execute arbitrary code.(CVE-2016-5423)

  - A flaw was found in the way PostgreSQL client programs
    handled database and role names containing newlines,
    carriage returns, double quotes, or backslashes. By
    crafting such an object name, roles with the CREATEDB
    or CREATEROLE option could escalate their privileges to
    superuser when a superuser next executes maintenance
    with a vulnerable client program.(CVE-2016-5424)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://developer.huawei.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1058
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b01b591d");
  script_set_attribute(attribute:"solution", value:
"Update the affected postgresql packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:postgresql-test");
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

pkgs = ["postgresql-9.2.18-1",
        "postgresql-contrib-9.2.18-1",
        "postgresql-devel-9.2.18-1",
        "postgresql-docs-9.2.18-1",
        "postgresql-libs-9.2.18-1",
        "postgresql-plperl-9.2.18-1",
        "postgresql-plpython-9.2.18-1",
        "postgresql-pltcl-9.2.18-1",
        "postgresql-server-9.2.18-1",
        "postgresql-test-9.2.18-1"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql");
}
