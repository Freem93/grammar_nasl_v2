#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99857);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/04 13:21:27 $");

  script_cve_id(
    "CVE-2016-9079",
    "CVE-2016-9893",
    "CVE-2016-9895",
    "CVE-2016-9897",
    "CVE-2016-9898",
    "CVE-2016-9899",
    "CVE-2016-9900",
    "CVE-2016-9901",
    "CVE-2016-9902",
    "CVE-2016-9904",
    "CVE-2016-9905",
    "CVE-2017-5373",
    "CVE-2017-5375",
    "CVE-2017-5376",
    "CVE-2017-5378",
    "CVE-2017-5380",
    "CVE-2017-5383",
    "CVE-2017-5386",
    "CVE-2017-5390",
    "CVE-2017-5396"
  );
  script_osvdb_id(
    147993,
    148666,
    148667,
    148668,
    148693,
    148695,
    148696,
    148697,
    148698,
    148699,
    148700,
    148701,
    148704,
    148705,
    148706,
    148707,
    148708,
    148709,
    148710,
    148711,
    150831,
    150832,
    150834,
    150836,
    150837,
    150858,
    150859,
    150860,
    150861,
    150862,
    150863,
    150864,
    150865,
    150866,
    150875,
    150878,
    150881
  );

  script_name(english:"EulerOS 2.0 SP2 : firefox (EulerOS-SA-2017-1011)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the firefox package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - Multiple flaws were found in the processing of
    malformed web content. A web page containing malicious
    content could cause Firefox to crash or, potentially,
    execute arbitrary code with the privileges of the user
    running Firefox.
    (CVE-2016-9079,CVE-2016-9893,CVE-2016-9895,CVE-2016-989
    7,CVE-2016-9898,CVE-2016-9899,CVE-2016-9900,CVE-2016-99
    01,CVE-2016-9902,CVE-2016-9904,CVE-2016-9905,CVE-2017-5
    373, CVE-2017-5375, CVE-2017-5376, CVE-2017-5378,
    CVE-2017-5380, CVE-2017-5383, CVE-2017-5386,
    CVE-2017-5390, CVE-2017-5396)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://developer.huawei.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1011
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9429a164");
  script_set_attribute(attribute:"solution", value:
"Update the affected firefox packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox nsSMILTimeContainer::NotifyTimeChange() RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:firefox");
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
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

flag = 0;

pkgs = ["firefox-45.7.0-1.0.1"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg, allowmaj:TRUE)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox");
}
