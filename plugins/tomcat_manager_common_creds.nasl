#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34970);
  script_version ("$Revision: 1.36 $");
  script_cvs_date("$Date: 2017/01/31 14:53:42 $");

  script_cve_id(
   "CVE-2009-3099",
   "CVE-2009-3548",
   "CVE-2010-0557",
   "CVE-2010-4094"
  );
  script_bugtraq_id(
    36253,
    36954,
    37086,
    38084,
    44172
  );
  script_osvdb_id(
    57898,
    60176,
    60317,
    62118,
    69008
  );
  script_xref(name:"EDB-ID", value:"18619");
  script_xref(name:"EDB-ID", value:"31433");
  script_xref(name:"ZDI", value:"ZDI-10-214");

  script_name(english:"Apache Tomcat Manager Common Administrative Credentials");
  script_summary(english:"Try common passwords for Tomcat.");
 
  script_set_attribute(attribute:"synopsis", value:
"The management console for the remote web server is protected using a
known set of credentials.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to gain access to the Manager web application for the
remote Tomcat server using a known set of credentials. A remote
attacker can exploit this issue to install a malicious application on
the affected server and run arbitrary code with Tomcat's privileges
(usually SYSTEM on Windows, or the unprivileged 'tomcat' account on
Unix). Note that worms are known to propagate this way.");
  script_set_attribute(attribute:"see_also", value:"http://markmail.org/thread/wfu4nff5chvkb6xp");
  script_set_attribute(attribute:"see_also", value:"http://svn.apache.org/viewvc?view=revision&revision=834047");
  # https://web.archive.org/web/20091221100437/http://www.intevydis.com/blog/?p=87
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e7339edb");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-214/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/Oct/259");
  script_set_attribute(attribute:"solution", value:
"Edit the associated 'tomcat-users.xml' file and change or remove the
affected set of credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Tomcat Manager Authenticated Upload Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(255);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK); 
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
  script_family(english: "Web Servers");
  script_dependencie("http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/tomcat");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");

if (supplied_logins_only)
  audit(AUDIT_SUPPLIED_LOGINS_ONLY);

n = 0;
user[n] = "tomcat";	pass[n++] = "tomcat";
user[n] = "tomcat";	pass[n++] = "";
user[n] = "tomcat"; pass[n++] = "admin";
user[n] = "admin";	pass[n++] = "admin";
user[n] = "admin";	pass[n++] = "";
user[n] = "admin";	pass[n++] = "password";
user[n] = "password";	pass[n++] = "password";
# HP Operations Manager 8.10 (BID 37086)
user[n] = "ovwebusr";   pass[n++] = "OvW*busr1";
user[n] = "j2deployer"; pass[n++] = "j2deployer";
# IBM Cognos Express (BID 38084)
user[n] = "cxsdk";      pass[n++] = "kdsxc";
# IBM Rational Quality Manager and Test Lab Manager (CVE-2010-4094 / BID 44172)
user[n] = "ADMIN";   pass[n++] = "ADMIN";
user[n] = "manager"; pass[n++] = "manager"; # WaveMaker 6.4, and probably several other apps
user[n] = "admin";   pass[n++] = "tomcat";
user[n] = "admin";   pass[n++] = "j5Brn9";
user[n] = "both";    pass[n++] = "tomcat";
user[n] = "role";    pass[n++] = "changethis";
user[n] = "role1";   pass[n++] = "role1";
user[n] = "role1";   pass[n++] = "tomcat7";
user[n] = "root";    pass[n++] = "root";
user[n] = "root";    pass[n++] = "changethis";
user[n] = "root";    pass[n++] = "owaspbwa"; # OWASP Broken Web Applications
user[n] = "tomcat";  pass[n++] = "changethis";
user[n] = "xampp";   pass[n++] = "xampp";
user[n] = "tomcat";  pass[n++] = "s3cret";
user[n] = "QCC";     pass[n++] = "QLogic66"; # QLogic QConvergeConsole

port = get_http_port(default:8080);

if (!thorough_tests)
{
 banner = get_http_banner(port: port);
 if (banner !~ "Apache(-|\s)Coyote")
  audit(AUDIT_WRONG_WEB_SERVER, port, "Apache Tomcat");
}

function test(port, user, pass, page)
{
 local_var	r;

 r = http_send_recv3(
   port : port,
   username : user,
   password : pass,
   method : "GET",
   item : "/" + page,
   exit_on_fail : TRUE
 );

 if (r[0] !~ "^HTTP/1\.[01] 200 ") return 0;
 if ("Apache Software Foundation" >!< r[2]) return 0;

 if (r[2] !~ "AutoDeploy|(deploy|install)Config|>Tomcat Version<|DeployXML|(deploy|install)War") return 0;

 return 1;
}

urls = make_list("manager/html", "host-manager/html", "manager/status");

install = build_url(port: port, qs:"");
report = '';

foreach u (urls)
{
  clear_cookiejar();

  r = http_send_recv3(
    port : port,
    method : "GET",
    item : "/" + u,
    username : "",
    password : "",
    exit_on_fail : TRUE
  );

  if (r[0] !~ "^HTTP/1\.[01] 401 ") continue;
  if (r[1] !~ "Tomcat (Host )?Manager Application") continue;

  for (i = 0; i < n; i ++)
  {
    if (test(port: port, user: user[i], pass: pass[i], page: u))
    {
      report +=
        '\n  URL      : ' + install + u +
        '\n  Username : ' + user[i] +
        '\n  Password : ' + pass[i] + '\n';
      break;
    }
  }
}

if (!empty_or_null(report))
{
  report1 = '\nIt was possible to log into the Tomcat Manager web app using the\nfollowing info :\n' + report;
  security_hole(port:port, extra:report1);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Apache Tomcat", port);
