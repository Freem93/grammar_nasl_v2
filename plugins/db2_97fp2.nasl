#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46766);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/12/06 20:03:50 $");

  script_cve_id(
    "CVE-2009-3471",
    "CVE-2009-3555",
    "CVE-2010-0462",
    "CVE-2010-0472",
    "CVE-2010-3193",
    "CVE-2010-3194",
    "CVE-2010-3195",
    "CVE-2010-3196",
    "CVE-2010-3197",
    "CVE-2011-0757"
  );
  script_bugtraq_id(36540, 36935, 37976, 38018, 40446);
  script_osvdb_id(
    58477,
    62063,
    62130,
    64040,
    65148,
    65149,
    67702,
    67703,
    67704,
    70773
  );
  script_xref(name:"Secunia", value:"38294");
  script_xref(name:"Secunia", value:"40003");

  script_name(english:"IBM DB2 9.7 < Fix Pack 2 Multiple Vulnerabilities");
  script_summary(english:"Checks DB2 signature");

  script_set_attribute(attribute:"synopsis",value:
"The remote database server is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",value:
"According to its version, the installation of IBM DB2 9.7 running on
the remote host is affected by one or more of the following issues :

  - The 'MODIFIED SQL DATA' table function is not dropped
    when a definer loses required privileges to maintain
    the objects. (IC63548)

  - A privilege escalation vulnerability exists in the
    DB2STST program (on Linux and Unix platforms only). 
    (IC65742)

  - A malicious user could use the DB2DART program to 
    overwrite files owned by the instance owner. (IC65762)

  - The scalar function REPEAT contains a buffer overflow
    that a malicious user with a valid database connection 
    could manipulate, causing the DB2 server to trap. 
    (IC65935)

  - Special group and user enumeration operation on the DB2 
    server or DB2 Administrator Server (DAS) could trap 
    when running on Windows 2008. (IC66643)

  - It is possible to execute non-DDL statements even after
    an user's DBADM authority has been revoked. (IC66815)

  - If the database configuration parameter 'AUTO_REVAL' is
    set to 'IMMEDIATE', system granted privileges are not
    regenerated. (IC67008)

  - 'Monitor Administrative Views' available in SYSIBMADM
    schema are publicly viewable. (IC67819)

  - A weakness in the SSL v3 / TLS protocol involving
    session renegotiation may allow an attacker to inject 
    an arbitrary amount of plaintext into the beginning of
    the application protocol stream, which could facilitate
    man-in-the-middle attacks. (IC68055)

  - By sending a specially crafted packet to the Tivoli 
    Monitoring Agent (KUDDB2), which listens on TCP port 
    6014 by default, it may be possible to trigger a denial 
    of service condition. (IC68762)");

  script_set_attribute(attribute:"see_also",value:"http://intevydis.blogspot.com/2010/01/ibm-db2-97-kuddb2-dos.html");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC63548");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC65742");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC65762");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC65935");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC66643");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC66815");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC67008");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC67819");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC68055");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC68762");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg21432298");
  script_set_attribute(attribute:"solution",value:"Apply IBM DB2 version 9.7 Fix Pack 2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 310);

  script_set_attribute(attribute:"vuln_publication_date", value: "2010/05/28"); # DB2 9.7.2 release date.
  script_set_attribute(attribute:"patch_publication_date", value: "2010/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value: "2010/06/01");
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

level = get_kb_item_or_exit("DB2/"+port+"/Level");
if (level !~ '^9\\.7\\.') exit(0, "The version of IBM DB2 listening on port "+port+" is not 9.7 and thus is not affected.");

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
  fixed_level = '9.7.200.358';
  if (ver_compare(ver:level, fix:fixed_level) == -1)
    report =
      '\n  Platform        : ' + platform_name +
      '\n  Installed level : ' + level +
      '\n  Fixed level     : ' + fixed_level + '\n';
}
# Linux, 2.6 Kernel 32/64-bit
else if (platform == 18 || platform == 30)
{
  fixed_level = '9.7.0.2';
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
