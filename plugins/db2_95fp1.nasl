#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33763);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/12/06 20:03:50 $");

  script_cve_id(
    "CVE-2008-1966",
    "CVE-2008-1997",
    "CVE-2008-1998",
    "CVE-2008-3852",
    "CVE-2008-3854"
  );
  script_bugtraq_id(
    28835,
    28836,
    28843
  );
  script_osvdb_id(
    41631,
    41796,
    44963,
    46263,
    46264,
    46265,
    46266,
    46267,
    46270,
    143790
  );

  script_name(english:"IBM DB2 < 9.5 Fix Pack 1 Multiple Vulnerabilities");
  script_summary(english:"Checks DB2 signature.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installation of IBM DB2 9.5 running on the remote host does not
have any Fix Packs applied. It is, therefore, affected by one or more
of the following issues :

  - There is a security vulnerability in the 'NNSTAT'
    procedure on Windows platforms only that allows low-
    privileged users to overwrite arbitrary files.
    (IZ10776)

  - There is a security vulnerability in the
    'SYSPROC.ADMIN_SP_C' procedure on Windows platforms 
    that allows users to load arbitrary library and 
    execute arbitrary code in the system. (IZ10917)

  - An unspecified vulnerability affects 'DB2WATCH' and
    'DB2FREEZE' on Solaris platforms. (IZ12994)

  - An authenticated, remote user can cause the DB2 instance
    to crash by passing specially crafted parameters to 
    the 'RECOVERJAR' and 'REMOVE_JAR' procedures. (IZ15496)

  - There is an internal buffer overflow vulnerability in
    the DAS process that could allow arbitrary code 
    execution on the affected host. (IZ12406)

  - A local attacker can create arbitrary files as root 
    on Unix and Linux platforms using symlinks to the 
    'dasRecoveryIndex', 'dasRecoveryIndex.tmp', 
    '.dasRecoveryIndex.lock', and 'dasRecoveryIndex.cor' 
    files during initialization. (IZ12798)

  - There are possible buffer overflows involving 'XQUERY', 
    'XMLQUERY', 'XMLEXISTS', and 'XMLTABLE'. (IZ18431)

  - There is a security vulnerability related to a 
    failure to switch the owner of the 'db2fmp' process
    affecting Unix and Linux platforms. (IZ19155)

  - When a memory dump occurs, the password used to connect
    to the database remains visible in plaintext in the 
    memory dump file. (JR28314)

  - The CLR stored procedure deployment feature of IBM 
    Database Add-Ins for Visual Studio can be used to
    escalate privileges or launch a denial of service
    attack against a DB2 server. (JR28431)

  - A flaw exists in the db2ls command that allows a local
    attacker to write to any file on the system through the
    use of symbolic links. Note that this issue does not
    affect Windows systems. (IZ14939)");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/491071/100/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/491073/100/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/491075/100/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/496406/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/496405/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ10776");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ10917");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ12406");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ12798");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ18431");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ19155");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1JR28314");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1JR28431");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ14939");
  script_set_attribute(attribute:"solution", value:"Apply IBM DB2 version 9.5 Fix Pack 1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94, 119, 264);

  script_set_attribute(attribute:"plugin_publication_date", value: "2008/07/30");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");
 
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 
  script_dependencies("db2_das_detect.nasl");
  script_require_ports("Services/db2das", 523);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:'db2das', default:523, exit_on_fail:TRUE);

level = get_kb_item_or_exit("DB2/" + port + "/Level");
if (level !~ '^9\\.5\\.') exit(0, "The version of IBM DB2 listening on port "+port+" is not 9.5 and thus is not affected.");

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

# Windows 32-bit
if (platform == 5)
{
  fixed_level = '9.5.100.179';
  if (ver_compare(ver:level, fix:fixed_level) == -1)
    report =
      '\n  Platform        : ' + platform_name +
      '\n  Installed level : ' + level +
      '\n  Fixed level     : ' + fixed_level + '\n';
}
# Linux, 2.6 Kernel 32-bit
else if (platform == 18)
{
  fixed_level = '9.5.0.1';
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
