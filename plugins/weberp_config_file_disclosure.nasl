#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
 script_id(11639);
 script_version ("$Revision: 1.18 $");

 script_cve_id("CVE-2003-1383");
 script_bugtraq_id(6996);
 script_osvdb_id(59536);

 script_name(english:"webERP Configuration File Remote Access");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that is affected by
an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is using webERP, a web-based accounting / ERP
software. 

There is a flaw in the version of webERP on the remote host such that
an attacker is able to download the application's configuration file,
'logicworks.ini', containing the database username and password." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/313575" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to webERP 0.1.5 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(264);
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/20");
 script_cvs_date("$Date: 2011/03/13 23:54:24 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Determines if webERP is installed");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

foreach d ( cgi_dirs() )
{
 r = http_send_recv3(method:"GET",item:d + "/logicworks.ini", port:port);
 if (isnull(r)) exit(0);
 res = r[2];
 if("$CompanyName" >< res && "WEB-ERP" >< res )
 	{
	  if (report_verbosity > 0)
	    security_hole(port:port, extra: res);
	  else
	    security_hole(port:port);
	  exit(0);
	}
}
