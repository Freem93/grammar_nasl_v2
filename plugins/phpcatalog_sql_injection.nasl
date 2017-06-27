#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11969);
 script_version("$Revision: 1.18 $");
 script_bugtraq_id(9318);
 script_osvdb_id(3303);

 script_name(english:"PHPCatalog id Parameter SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to SQL injection." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running PHPCatalog, a CGI suite to
handle on-line catalogues.

There is a flaw in the remote software that could allow anyone to
inject arbitrary SQL commands, which could in turn be used to gain
administrative access on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://xforce.iss.net/xforce/xfdb/14116" );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/advisories/10516/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHPCatalog 2.6.10 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/12/31");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/12/30");
 script_cvs_date("$Date: 2011/12/16 23:13:20 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"SQL Injection");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("webmirror.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

# Check starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port))exit(0);


function check(dir)
{
  local_var buf, r;
  r = http_send_recv3(method: "GET", item: strcat(dir, "/index.php?id='"), port:port);
  if (isnull(r)) exit(0);
  buf = strcat(r[0], r[1], '\r\n', r[2]);
  if("FROM phpc_catalog prod " >< buf )
  	{
	security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
	}
 
 
 return(0);
}

foreach dir ( cgi_dirs() )
{
 check(dir:dir);
}
