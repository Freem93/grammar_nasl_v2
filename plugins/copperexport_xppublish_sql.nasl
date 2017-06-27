#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(17306);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2005-0697");
 script_bugtraq_id(12740);
 script_osvdb_id(14598);

 name["english"] = "CopperExport XP_Publish.PHP SQL Injection Vulnerability";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running CopperExport, a plugin for iPhoto that
allows an iPhoto user to export images to a Coppermine gallery. 

The remote version of this software fails to sanitize unspecified
input to the 'xp_publish.php' script before using it in a SQL query. 

Note that successful exploitation requires that an attacker be
authenticated." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/advisories/14401" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CopperExport 0.2.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/25");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "SQL Injection in CopperExport";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


global_var port;

function check(dir)
{
  local_var buf, r;

  r = http_send_recv3(method:"GET", item:dir + "/ChangeLog", port:port, exit_on_fail: 1);
  buf = strcat(r[0], r[1], '\r\n', r[2]);

  if("initial release of CopperExport." ><  buf &&
     "Version 0.2.1" >!< buf )
  	{
	security_warning(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
	}
 
 
 return(0);
}

port = get_http_port(default:80, embedded: 0, php: 1);


foreach dir (cgi_dirs()) check( dir : dir );
