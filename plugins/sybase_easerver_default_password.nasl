#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19218);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_bugtraq_id(14287);
  script_osvdb_id(17996);

  script_name(english:"Sybase EAServer WebConsole jaqadmin Default Password");
  script_summary(english:"Checks for default administrator password in Sybase EAServer");

  script_set_attribute(attribute:"synopsis", value:"The remote service is configured with a default administrator password.");

  script_set_attribute(
    attribute:"description",
    value:
"This host appears to be the running the Sybase EAServer Management with
the default administrator accounts still configured (jagadmin/'').  A
potential intruder could reconfigure this service in a way that grants
system access."
  );
  script_set_attribute(attribute:"solution", value:"Change default administrator password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sybase EAServer 5.2 Remote Stack Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Jul/245");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_dependencies("find_service1.nasl", "http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only", "Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);
  exit(0);
}

# Check starts here
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


global_var	port;

function check(dir)
{
 local_var	r, val, variables;

 erase_http_cookie(name: "JAGID");
 r = http_send_recv3(method: "GET", item: string(dir, "/Login.jsp"), port:port);
 if (isnull(r)) exit(0);
 if ("Sybase Management Console Login" >< r[2])
 {
  variables = "j_username=jagadmin&j_password=&submit.x=29&submit.y=10&submit=login";
  r = http_send_recv3(method: "POST", item: dir+"/j_security_check", data: variables, port: port,
   content_type: "application/x-www-form-urlencoded" );
  if (isnull(r)) exit(0);

  val = get_http_cookie(name: "JAGID");
  if (! isnull(val))
  {
   security_hole(port);
   exit(0);
  }
 }

 return(0);
}

port = get_http_port(default:8080);
banner = get_http_banner (port:port);
if ("Server: Jaguar Server Version" >!< banner)
  exit (0);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

init_cookiejar();
foreach dir (make_list(cgi_dirs(), "/WebConsole"))
{
 check(dir:dir);
}
