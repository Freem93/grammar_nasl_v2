#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28227);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/12/06 20:03:50 $");

  script_cve_id(
    "CVE-2007-3676",
    "CVE-2007-5652",
    "CVE-2007-5757",
    "CVE-2007-6045",
    "CVE-2007-6046",
    "CVE-2007-6047",
    "CVE-2007-6048",
    "CVE-2007-6049",
    "CVE-2007-6050",
    "CVE-2007-6051",
    "CVE-2007-6052",
    "CVE-2007-6053",
    "CVE-2008-0698"
  );
  script_bugtraq_id(26450, 27680, 27681);
  script_osvdb_id(
    40995,
    41008,
    41010,
    41011,
    41012,
    41013,
    41014,
    41015,
    41016,
    41017,
    41629,
    41630,
    41632,
    54035
  );

  script_name(english:"IBM DB2 < 9 Fix Pack 4 Multiple Vulnerabilities");
  script_summary(english:"Checks DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 running on the
remote host is affected by one or more of the following issues :

  - The 'db2dart' tool executes the 'tput' command which
    effectively allows a malicious user to run commands 
    as the DB2 instance owner (IZ03646).

  - 'db2watch' and 'db2freeze' have some unspecified
    vulnerability (IZ03655).

  - Incorrect permissions on ACLs for 'DB2NODES.CFG'
    (JR26989).

  - A local user may be able to gain root privileges using
    an unspecified vulnerability in several set-uid
    binaries (IZ07018).

  - A buffer overflow and invalid memory access 
    vulnerability exists in the DAS server code (unknown).");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6734f378");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ba276a6");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Feb/72");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Feb/73");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21255607");
  script_set_attribute(attribute:"solution", value:"Apply IBM DB2 version 9 Fix Pack 4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 264, 399);

  script_set_attribute(attribute:"plugin_publication_date", value: "2007/11/16");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");
 
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
 
  script_dependencies("db2_das_detect.nasl");
  script_require_ports("Services/db2das", 523);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:'db2das', default:523, exit_on_fail:TRUE);

level = get_kb_item_or_exit("DB2/" + port + "/Level");
if (level !~ '^9\\.[01]\\.') exit(0, "The version of IBM DB2 listening on port "+port+" is not 9.0 or 9.1 and thus is not affected.");

platform = get_kb_item_or_exit("DB2/"+port+"/Platform");
platform_name = get_kb_item("DB2/"+port+"/Platform_Name");
if (isnull(platform_name))
{
  platform_name = platform;
  report_phrase = "platform " + platform;
}
else
  report_phrase = platform_name;
report = "";

# Windows, x86 32-bit
if (platform == 5)
{
  fixed_level = '9.1.400.359';
  if (ver_compare(ver:level, fix:fixed_level) == -1)
    report =
      '\n  Platform        : ' + platform_name +
      '\n  Installed level : ' + level +
      '\n  Fixed level     : ' + fixed_level + '\n';
}
# Linux, x86 2.6 kernel 32-bit
else if (platform == 18)
{
  fixed_level = '9.1.0.4';
  if (ver_compare(ver:level, fix:fixed_level) == -1)
    report = 
      '\n  Platform        : ' + platform_name +
      '\n  Installed level : ' + level +
      '\n  Fixed level     : ' + fixed_level + '\n';
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

if (report)
{
  if (report_verbosity > 0) security_hole(port:port, extra:report);
  else security_hole(port);
}
else exit(0, "IBM DB2 "+level+" on " + report_phrase + " is listening on port "+port+" and is not affected.");
