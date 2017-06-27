#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76114);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/08/03 14:14:44 $");

  script_cve_id("CVE-2013-6744", "CVE-2013-6747", "CVE-2014-0907", "CVE-2014-0963");
  script_bugtraq_id(65156, 67238, 67616, 67617);
  script_osvdb_id(102556, 106786, 107412, 107413);

  script_name(english:"IBM DB2 9.7 < Fix Pack 9a Multiple Vulnerabilities");
  script_summary(english:"Checks the DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of DB2 9.7 running on the
remote host is prior to Fix Pack 9a. It is, therefore, affected by one
or more of the following vulnerabilities :

  - An unspecified error exists related to handling
    malformed certificate chains that allows denial
    of service attacks. (CVE-2013-6747)

  - A build error exists related to libraries in insecure
    locations that allows a local user to carry out
    privilege escalation attacks. Note that this issue does
    not affect the application when running on Microsoft
    Windows operating systems. (CVE-2014-0907)

  - An unspecified error exists related to the TLS
    implementation that allows certain error cases to cause
    100% CPU utilization. (CVE-2014-0963)");
  # Advisories
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21672100");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21671732");
  # Security Fix List
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21450666#9a");
  # Downloads
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24037559");
  script_set_attribute(attribute:"solution", value:
"Apply IBM DB2 version 9.7 Fix Pack 9a or later.

Alternatively, in the case of DB2 Version 9.7 Fix Pack 8, contact the
vendor to obtain a special build with the interim fix.

Note that the vendor has posted a workaround for the build error issue
(CVE-2014-0907) involving the command 'sqllib/bin/db2chglibpath'.
Please consult the advisory for detailed instructions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("db2_das_detect.nasl");
  script_require_ports("Services/db2das", 523);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"db2das", default:523, exit_on_fail:TRUE);

level = get_kb_item_or_exit("DB2/" + port + "/Level");
if (level !~ "^9\.7\.") audit(AUDIT_NOT_LISTEN, "DB2 9.7", port);

platform = get_kb_item_or_exit("DB2/"+port+"/Platform");
platform_name = get_kb_item("DB2/"+port+"/Platform_Name");
if (isnull(platform_name))
{
  platform_name = platform;
  report_phrase = "platform " + platform;
}
else
  report_phrase = platform_name;

report = NULL;

# Windows 32-bit/64-bit
if (platform == 5 || platform == 23)
{
  fixed_level = '9.7.901.409';
  if (ver_compare(ver:level, fix:fixed_level) == -1)
    report =
      '\n  Platform        : ' + platform_name +
      '\n  Installed level : ' + level +
      '\n  Fixed level     : ' + fixed_level + ' (9.7 Fix Pack 9a)\n';

  # In the case of a non-paranoid scan and FP8,
  # do not report.
  # It's not clear if the special build will
  # change the build level.
  if (level == '9.7.800.717' && report_paranoia < 2)
    exit(1, "Nessus is unable to determine if the patch has been applied or not.");
}
# Others
else if (
  # Linux, 2.6 kernel 32/64-bit
  platform == 18 ||
  platform == 30 ||
  # AIX
  platform == 20
)
{
  fixed_level = '9.7.0.9';
  if (ver_compare(ver:level, fix:fixed_level) <= 0)
    report =
      '\n  Platform        : ' + platform_name +
      '\n  Installed level : ' + level +
      '\n  Fixed level     : 9.7.0.9a (9.7 Fix Pack 9a)\n';

  # If not paranoid and at 9.7.0.9/9.7.0.8 already,
  # do not report - we cannot tell if the special
  # build or FP9a is there.
  if ((level == fixed_level || level == '9.7.0.8') && report_paranoia < 2)
    exit(1, "Nessus is unable to determine if the patch has been applied or not.");
}
else
{
  info =
    'Nessus does not support version checks against ' + report_phrase + '.\n' +
    'To help us better identify vulnerable versions, please send the platform\n' +
    'number along with details about the platform, including the operating system\n' +
    'version, CPU architecture, and DB2 version to db2-platform-info@nessus.org.\n';
  exit(1, info);
}

if (!isnull(report))
{
  if (report_verbosity > 0) security_hole(port:port, extra:report);
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "DB2", port, level);
