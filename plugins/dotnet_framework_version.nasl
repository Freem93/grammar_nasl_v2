#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(24243);
 script_version ("$Revision: 1.9 $");
 script_cvs_date("$Date: 2011/03/14 21:48:03 $");
 
 script_name(english:"Microsoft .NET Version Information Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the version number of the remote installation
of Microsoft .NET Framework." );
 script_set_attribute(attribute:"description", value:
"By requesting a non-existent .aspx file on the remote web server, it
is possible to obtain the exact version number of the remote .NET
framework." );
 script_set_attribute(attribute:"solution", value:
"Configure IIS to return custom error messages instead of the default
.NET error messages by setting the option 'customErrors mode' to 'On'
or 'RemoteOnly'." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/01/26");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Checks for the version of the .NET framework");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("dotnet_framework_handlers.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
exts = get_kb_list("www/" + port + "/.NetExtensions");
ext  = ".aspx";
if ( ! isnull(exts) ) 
{
  exts = make_list(exts);
  foreach item ( exts )
	{
	  if ( item == ".mspx" || item == ".ashx") ext = item;
	}
}

u = strcat("/", rand_str(length:8), ext);
r = http_send_recv3(port:port, method: "GET", item: u);
# Multi-lingual support
line = egrep(pattern:"Microsoft \.NET Framework.*:[0-9.]+.*ASP\.NET.*[0-9.]+", string: r[2]);
if ( line )
{
 line = ereg_replace(pattern:".*<b>.*</b>&nbsp;", 	
		      replace:"",
		     string:line);
 framework_version = ereg_replace(pattern:".*:([0-9.]+).*ASP\.NET.*",
				  replace:"\1",
				  string:line);
 asp_version = ereg_replace(pattern:".*:[0-9.]+.*ASP\.NET.*:([0-9.]+).*",
				  replace:"\1",
				  string:line);

 set_kb_item(name:"www/" + port + "/Microsoft_.NET_Framework_Version", value:framework_version);
 set_kb_item(name:"www/" + port + "/ASP.NET_Version", value:asp_version);
 set_kb_item(name:"Services/www/ASP.Net", value:port);
 security_note(port:port, extra: line);
}
