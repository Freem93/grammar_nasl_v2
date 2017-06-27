#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99765);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/04 13:21:26 $");

  script_cve_id(
    "CVE-2016-1952",
    "CVE-2016-1954",
    "CVE-2016-1957",
    "CVE-2016-1958",
    "CVE-2016-1960",
    "CVE-2016-1961",
    "CVE-2016-1962",
    "CVE-2016-1964",
    "CVE-2016-1965",
    "CVE-2016-1966",
    "CVE-2016-1973",
    "CVE-2016-1974",
    "CVE-2016-1977",
    "CVE-2016-2790",
    "CVE-2016-2791",
    "CVE-2016-2792",
    "CVE-2016-2793",
    "CVE-2016-2794",
    "CVE-2016-2795",
    "CVE-2016-2796",
    "CVE-2016-2797",
    "CVE-2016-2798",
    "CVE-2016-2799",
    "CVE-2016-2800",
    "CVE-2016-2801",
    "CVE-2016-2802"
  );
  script_osvdb_id(
    135550,
    135551,
    135552,
    135553,
    135554,
    135555,
    135556,
    135557,
    135558,
    135576,
    135579,
    135580,
    135582,
    135583,
    135584,
    135591,
    135592,
    135595,
    135601,
    135602,
    135605,
    135606,
    135607,
    135608,
    135609,
    135610,
    135611,
    135612,
    135613,
    135614,
    135615,
    135616,
    135617,
    135618
  );

  script_name(english:"EulerOS 2.0 SP1 : firefox (EulerOS-SA-2016-1002)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the firefox package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - Several flaws were found in the processing of malformed
    web content. A web page containing malicious content
    could cause Firefox to crash or, potentially, execute
    arbitrary code with the privileges of the user running
    Firefox. (CVE-2016-1952, CVE-2016-1954, CVE-2016-1957,
    CVE-2016-1958, CVE-2016-1960, CVE-2016-1961,
    CVE-2016-1962, CVE-2016-1973, CVE-2016-1974,
    CVE-2016-1964, CVE-2016-1965, CVE-2016-1966)

  - Multiple security flaws were found in the graphite2
    font library shipped with Firefox. A web page
    containing malicious content could cause Firefox to
    crash or, potentially, execute arbitrary code with the
    privileges of the user running Firefox. (CVE-2016-1977,
    CVE-2016-2790, CVE-2016-2791, CVE-2016-2792,
    CVE-2016-2793, CVE-2016-2794, CVE-2016-2795,
    CVE-2016-2796, CVE-2016-2797, CVE-2016-2798,
    CVE-2016-2799, CVE-2016-2800, CVE-2016-2801,
    CVE-2016-2802)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://developer.huawei.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1002
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e328b89");
  script_set_attribute(attribute:"solution", value:
"Update the affected firefox packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/09");
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

pkgs = ["firefox-38.7.0-1"];

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
