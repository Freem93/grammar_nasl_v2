#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99893);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/04 13:21:27 $");

  script_cve_id(
    "CVE-2017-5398",
    "CVE-2017-5400",
    "CVE-2017-5401",
    "CVE-2017-5402",
    "CVE-2017-5404",
    "CVE-2017-5405",
    "CVE-2017-5407",
    "CVE-2017-5408",
    "CVE-2017-5410",
    "CVE-2017-5428"
  );
  script_osvdb_id(
    153143,
    153173,
    153174,
    153175,
    153176,
    153177,
    153178,
    153179,
    153180,
    153181,
    153182,
    153183,
    153190,
    153191,
    153192,
    153193,
    153195,
    153198,
    153214,
    153959
  );

  script_name(english:"EulerOS 2.0 SP1 : firefox (EulerOS-SA-2017-1048)");
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
    running Firefox. (CVE-2017-5398, CVE-2017-5400,
    CVE-2017-5401, CVE-2017-5402, CVE-2017-5404,
    CVE-2017-5407, CVE-2017-5408, CVE-2017-5410,
    CVE-2017-5405,CVE-2017-5428)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://developer.huawei.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1048
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11185668");
  script_set_attribute(attribute:"solution", value:
"Update the affected firefox packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/09");
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
if (isnull(sp) || sp !~ "^(1)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1");

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

flag = 0;

pkgs = ["firefox-52.0-5.0.1.h1"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg, allowmaj:TRUE)) flag++;

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
