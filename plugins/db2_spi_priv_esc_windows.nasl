#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76116);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/05 14:49:54 $");

  script_cve_id("CVE-2013-6744");
  script_bugtraq_id(67616);
  script_osvdb_id(107412);

  script_name(english:"IBM DB2 Stored Procedure Infrastructure Privilege Escalation Vulnerability");
  script_summary(english:"Checks DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 running on the
remote host is affected by a privilege escalation vulnerability.

An error exists related to the Stored Procedure infrastructure and the
'CREATE_EXTERNAL_ROUTINE' authority that allows an authenticated user
to escalate privileges.");
  # Advisory
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21673947");
  script_set_attribute(attribute:"solution", value:
"Apply IBM DB2 version 9.7 Fix Pack 9a, 10.1 Fix Pack 3a, 10.5 Fix Pack
3a, or 10.5 Fix Pack 4.

Alternatively, in the case of DB2 version 9.5 Fix Pack 9 or Fix Pack
10, 9.7 Fix Pack 8, and 10.5 Fix Pack 2, contact the vendor to obtain
a special build with the interim fix.

Additionally, note that users of DB2 version 9.1 installations that
are under an extended support contract may contact vendor support to
obtain a patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("db2_das_detect.nasl");
  script_require_ports("Services/db2das", 523);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"db2das", default:523, exit_on_fail:TRUE);

level = get_kb_item_or_exit("DB2/" + port + "/Level");
if (level !~ "^10\.[15]\." && level !~ "^9\.[157]\.")
  audit(AUDIT_NOT_LISTEN, "DB2 9.1 / 9.5 / 9.7 / 10.1 / 10.5", port);

platform = get_kb_item_or_exit("DB2/"+port+"/Platform");
platform_name = get_kb_item("DB2/"+port+"/Platform_Name");
if (isnull(platform_name))
{
  platform_name = platform;
  report_phrase = "platform " + platform;
}
else
  report_phrase = platform_name;

report_fixed_level = NULL;

# Windows 32-bit/64-bit are affected
if (platform == 5 || platform == 23)
{
  # v9.1
  if (level =~ "^9\.1\." && report_paranoia > 1)
        report_fixed_level = 'See solution';

  # v9.5 <= 9.5 FP10
  else if (level =~ "^9\.5\.")
  {
    fixed_level = '9.5.1000.163';
    if (ver_compare(ver:level, fix:fixed_level) <= 0)
    {
      # If not paranoid and at 9.5.900.456/9.5.1000.163 already,
      # do not report - we cannot tell if special fix build is there.
      if (
        (level == '9.5.900.456' || level == '9.5.1000.163')
        &&
        report_paranoia < 2
      )
        exit(1, "Nessus is unable to determine if the patch has been applied or not.");
      else
        report_fixed_level = 'See solution';
    }
  }

  # v9.7 fp8 (requires special build)
  else if (
    level =~ "^9\.7\.8\d\d\." &&
    ver_compare(ver:level, fix:'9.7.800.717') <= 0
  )
  {
    # Do not report if at FP8 and not paranoid
    if (level == '9.7.800.717' && report_paranoia < 2)
      exit(1, "Nessus is unable to determine if the patch has been applied or not.");
    else
      report_fixed_level = 'See solution';
  }

  # v9.7 fp9a
  else if (
    level =~ "^9\.7\." &&
    ver_compare(ver:level, fix:'9.7.901.409') == -1
  )
    report_fixed_level = '9.7.901.409 (9.7 Fix Pack 9a)';
  # 10.1 FP3a
  else if (
    level =~ "^10\.1\.3\d\d\." &&
    ver_compare(ver:level, fix:'10.1.301.770') == -1
  )
    report_fixed_level = '10.1.301.770 (10.1 Fix Pack 3a) / 10.1.400.766 (10.1 Fix Pack 4)';
  # 10.5 FP2 (requires special build)
  else if (
    level =~ "^10\.5\.2\d\d\." &&
    ver_compare(ver:level, fix:'10.5.200.109') <= 0
  )
  {
    # Do not report if at FP2 and not paranoid
    if (level == '10.5.200.109' && report_paranoia < 2)
      exit(1, "Nessus is unable to determine if the patch has been applied or not.");
    else
      report_fixed_level = 'See solution';
  }
  # 10.5 FP3a
  else if (
    level =~ "^10\.5\." &&
    ver_compare(ver:level, fix:'10.5.301.84') == -1
  )
    report_fixed_level = '10.5.301.84 (10.5 Fix Pack 3a)';
  else
    exit(1, "Nessus is unable to determine if the patch has been applied or not.");
}
# Others (not affected, so audit)
else if (
  # Linux, 2.6 kernel 32/64-bit
  platform == 18 ||
  platform == 30 ||
  # AIX
  platform == 20
)
  audit(AUDIT_OS_NOT, "Microsoft Windows", "UNIX or Unix-like");
else
{
  info =
    'Nessus does not support version checks against ' + report_phrase + '.\n' +
    'To help us better identify vulnerable versions, please send the platform\n' +
    'number along with details about the platform, including the operating system\n' +
    'version, CPU architecture, and DB2 version to db2-platform-info@nessus.org.\n';
  exit(1, info);
}

if (!isnull(report_fixed_level))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Platform        : ' + platform_name +
      '\n  Installed level : ' + level +
      '\n  Fixed level     : ' + report_fixed_level + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "DB2", port, level);
