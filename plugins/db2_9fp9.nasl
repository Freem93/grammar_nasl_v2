#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46173);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/06 20:03:50 $");

  script_cve_id(
    "CVE-2009-3471",
    "CVE-2009-3555", 
    "CVE-2010-0462",
    "CVE-2010-3193",
    "CVE-2010-3194",
    "CVE-2010-3195"
  );
  script_bugtraq_id(36540, 36935, 37976);
  script_osvdb_id(58477, 64040, 64041, 67702, 67703, 67704);

  script_name(english:"IBM DB2 9.1 < Fix Pack 9 Multiple Vulnerabilities");
  script_summary(english:"Checks DB2 signature.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote database server is affected by multiple issues."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"According to its version, the installation of IBM DB2 9.1 running on
the remote host is affected by one or more of the following issues :

  - The 'MODIFIED SQL DATA' table function is not dropped
    when a definer loses required privileges to maintain
    the objects. (IZ46773)

  - A privilege escalation vulnerability exists in the
    DB2STST program (on Linux and Unix platforms only). 
    (IC65408)

  - A malicious user could use the DB2DART program to 
    overwrite files owned by the instance owner. (IC65749)

  - A heap overflow vulnerability exists in the 'REPEAT' 
    scalar function. A remote attacker with a valid 
    database connection could exploit this issue to execute
    arbitrary code subject to the privileges under which
    the database service operates. (IC65922)

  - Special group and user enumeration operation on the DB2 
    server or DB2 Administrator Server (DAS) could trap 
    when running on Windows 2008. (IC66099)

  - A weakness in the SSL v3 / TLS protocol involving
    session renegotiation may allow an attacker to inject 
    an arbitrary amount of plaintext into the beginning of
    the application protocol stream, which could facilitate
    man-in-the-middle attacks. (IC67848)"
  );
  script_set_attribute(attribute:"see_also", value:"http://intevydis.blogspot.com/2010/01/ibm-db2-97-heap-overflow.html");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ46773");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC65408");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC65749");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC65922");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC66099");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC67848");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21426108");
  script_set_attribute(attribute:"solution", value:"Apply IBM DB2 Version 9.1 Fix Pack 9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");
 
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
 
  script_dependencies("db2_das_detect.nasl");
  script_require_ports("Services/db2das", 523);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"db2das", default:523, exit_on_fail:TRUE);

level = get_kb_item("DB2/" + port + "/Level");
if (level !~ '^9\\.[01]\\.')  exit(0, "The version of IBM DB2 listening on port "+port+" is not 9.0 or 9.1 and thus is not affected.");

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

# Windows 32-bit/64-bit
if (platform == 5 || platform == 23)
{
  fixed_level = '9.1.900.215';
  if (ver_compare(ver:level, fix:fixed_level) == -1)
    report =
      '\n  Platform        : ' + platform_name +
      '\n  Installed level : ' + level +
      '\n  Fixed level     : ' + fixed_level + '\n';
}
else if (platform == 18 || platform == 30)
{
  fixed_level = '9.1.0.9';
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
  if (report_verbosity > 0) security_warning(port:port, extra:report);
  else security_warning(port);
}
else exit(0, "IBM DB2 "+level+" on " + report_phrase + " is listening on port "+port+" and is not affected.");
