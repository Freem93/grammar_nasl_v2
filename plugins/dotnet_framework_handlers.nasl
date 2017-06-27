#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(24242);
 script_version ("$Revision: 1.9 $");
 script_cvs_date("$Date: 2011/03/14 21:48:03 $");
 name["english"] = "Microsoft .NET Handlers Enumeration";
 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"It is possible to enumerate the remote .NET handlers used by the
remote web server." );
 script_set_attribute(attribute:"description", value:
"It is possible to obtain the list of handlers the remote ASP.NET web
server supports." );
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/815145" );
 script_set_attribute(attribute:"solution", value: "None" );
 script_set_attribute(attribute:"risk_factor", value: "None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/01/26");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();


 summary["english"] = "Checks for the version of the .NET framework";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


list = make_list(".ashx", ".aspx", ".asmx", ".rem", ".soap");
port = get_http_port(default:80, embedded: 0);


foreach ext (list) 
{
 u ="/" + rand_str(length:8) + ext;
 r = http_send_recv3(method: "GET", item: u, port:port);
 if ( "[FileNotFoundException]:" >< r[2] ||
      "[HttpException]:" >< r[2] ||
      "System.Runtime.Remoting.RemotingException:" >< r[2] ||
      egrep(pattern:"^Location:.*aspxerrorpath=", string:r[1]) )
	{
	 	rep += ' - ' + ext + '\n';
		set_kb_item(name:"www/" + port + "/.NetExtensions", value:ext);
	}
}


if ( rep )
{
 security_note(port:port,
		extra:'\nThe remote extensions are handled by the remote ASP.NET server :\n\n' + rep);

	
}
