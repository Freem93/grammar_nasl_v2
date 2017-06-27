#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(49120);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/12/06 20:03:50 $");

  script_cve_id(
    "CVE-2009-3471",
    "CVE-2009-3555",
    "CVE-2010-0462",
    "CVE-2010-3193",
    "CVE-2010-3194",
    "CVE-2010-3195",
    "CVE-2010-3731",
    "CVE-2010-3732",
    "CVE-2010-3733",
    "CVE-2010-3734",
    "CVE-2010-3735",
    "CVE-2010-3736",
    "CVE-2010-3737",
    "CVE-2010-3738",
    "CVE-2010-3739",
    "CVE-2010-3740"
  );
  script_bugtraq_id(36540, 36935, 37976, 40446, 43634, 43834);
  script_osvdb_id(
    58477,
    62063,
    64040,
    67702,
    67703,
    67704,
    68315,
    68402,
    68403,
    68404,
    68405,
    68406,
    68407,
    68408,
    68409,
    68410
  );
  script_xref(name:"Secunia", value:"41686");

  script_name(english:"IBM DB2 9.5 < Fix Pack 6a Multiple Vulnerabilities");
  script_summary(english:"Checks DB2 signature.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote database server is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the installation of IBM DB2 9.5 running on
the remote host is prior to 9.5 Fix Pack 6. It is, therefore, affected
by one or more of the following issues :

  - The Install component on Linux, UNIX, and Windows 
    enforces an unintended limit on password length, which
    makes it easier for attackers to obtain access via a 
    brute-force attack. (IC62856)
    
  - The Security component logs AUDIT events by using a 
    USERID and an AUTHID value corresponding to the instance 
    owner, instead of a USERID and an AUTHID value 
    corresponding to the logged-in user account, which makes
    it easier for remote, authenticated users to execute 
    Audit administration commands without discovery.
    (IC65184)

  - A privilege escalation vulnerability exists in the
    DB2STST program (on Linux and Unix platforms only). 
    (IC65703)

  - A malicious user could use the DB2DART program to 
    overwrite files owned by the instance owner. (IC65756)

  - The scalar function REPEAT contains a buffer overflow
    that a malicious user with a valid database connection 
    could manipulate, causing the DB2 server to trap. 
    (IC65933)

  - The Net Search Extender implementation in the Text 
    Search component does not properly handle an 
    alphanumeric Fuzzy search, which could allow a remote, 
    authenticated user to consume memory or even hang
    the system via the 'db2ext.textSearch' function.
    (IC66613)

  - Special group and user enumeration operation on the DB2 
    server or DB2 Administrator Server (DAS) could trap 
    when running on Windows 2008. (IC66642)

  - A weakness in the SSL v3 / TLS protocol involving
    session renegotiation may allow an attacker to inject 
    an arbitrary amount of plaintext into the beginning of
    the application protocol stream, which could facilitate
    man-in-the-middle attacks. (IC68054)

  - A memory leak in the Relational Data Services component,
    when the connection concentrator is enabled, allows 
    remote, authenticated users to cause a denial of service 
    (heap memory consumption) by using a different code page 
    than the database server. (IC68182)

  - An unspecified remote buffer overflow vulnerability exists
    in the DB2 administrative server. (IC70538)

  - The 'MODIFIED SQL DATA' table function is not dropped
    when a definer loses required privileges to maintain
    the objects. (IZ46774)

  - The DRDA Services component allows a remote, 
    authenticated user to cause the database server to 
    ABEND by using the client CLI on Linux, UNIX, or 
    Windows for executing a prepared statement with a large
    number of parameter markers. (IZ56428)

  - The 'Query Compiler, Rewrite, Optimizer' component 
    allows remote, authenticated users to cause a denial of
    service (CPU consumption) via a crafted query involving 
    certain UNION ALL views, leading to an indefinitely 
    large amount of compilation time. (IZ58417)

  - The Engine Utilities component uses world-writable 
    permissions for the 'sqllib/cfg/db2sprf' file, which
    could allow a local user to gain privileges by modifying
    this file. (IZ68463)

  - The audit facility in the Security component uses 
    instance-level audit settings to capture CONNECT and 
    AUTHENTICATION events in certain circumstances in which
    database-level audit settings were intended, which might 
    make it easier for remote attackers to connect without 
    discovery. (JR34218)

  - A memory leak in the Relational Data Services component 
    allows remote, authenticated users to cause a denial of
    service (heap memory consumption) by executing a user-
    defined function (UDF) or stored procedure while using a
    different code page than the database server. (LI75022)"
  );

  script_set_attribute(attribute:"see_also",value:"http://www.zerodayinitiative.com/advisories/ZDI-11-035");
  script_set_attribute(attribute:"see_also",value:"http://seclists.org/fulldisclosure/2011/Jan/582");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC62856");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC65703");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC65756");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC65933");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC66613");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC66642");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC68054");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC68182");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC65184");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg21444772");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ46774");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ56428");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ58417");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ68463");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg1JR34218");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg1LI75022");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg21293566");
  script_set_attribute(attribute:"solution",value:"Apply IBM DB2 version 9.5 Fix Pack 6a or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/07");
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

# Windowns 32-bit/64-bit
if (platform == 5 || platform == 23)
{
  fixed_level = '9.5.601.507';
  if (ver_compare(ver:level, fix:fixed_level) == -1)
    report = 
      '\n  Platform        : ' + platform_name +
      '\n  Installed level : ' + level +
      '\n  Fixed level     : ' + fixed_level + '\n';
}
# Linux, 2.6 kernel 32/64-bit
else if(platform == 18 || platform == 30 
    # AIX
    || platform == 20)
{
  fixed_level = '9.5.0.6';
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
