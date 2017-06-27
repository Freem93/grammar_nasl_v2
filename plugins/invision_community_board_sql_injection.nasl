#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16154);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2005-0217");
 script_bugtraq_id(12205);
 script_osvdb_id(12817);

 script_name(english:"Invision Community Blog Module eid Parameter SQL Injection");
 script_summary(english:"SQL Injection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is a hosting an application that is affected
by a SQL injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Invision Community Blog, a
weblog utility.

There is a flaw in the remote software that could allow anyone to 
inject arbitrary SQL commands through the 'index.php' script, which
may in turn be used to gain administrative access on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Jan/84" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2679d827" );
 script_set_attribute(attribute:"solution", value:
"Patches are available from the above reference." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/09");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie( "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/invision_power_board");
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if ( ! can_host_php(port:port) ) exit(0);

function check(dir)
{
  local_var res;

  res = http_send_recv3(method:"GET", item:string(dir, "/index.php?automodule=blog&blogid=1&cmd=showentry&eid=1'"), port:port);
  if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

  if("SELECT * FROM ibf_blog_entries WHERE blog_id=1 and entry_id" >< res[2] )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
 
 
 return(0);
}


foreach dir (cgi_dirs()) 
 {
  check(dir:dir);
 }
