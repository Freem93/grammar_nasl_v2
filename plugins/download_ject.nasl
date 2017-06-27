#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12287);
 
 script_version("$Revision: 1.11 $");

 script_name(english:"Microsoft IIS Download.Ject Trojan Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is infected by a Trojan Horse." );
 script_set_attribute(attribute:"description", value:
"Download.Ject is a Trojan that infects Microsoft IIS servers.

The Trojan's dropper sets it as the document footer for all pages 
served by IIS Web sites on the infected computer." );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/security/incident/download_ject.mspx" );
 script_set_attribute(attribute:"solution", value:
"Use an antivirus to clean machine." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");


 script_set_attribute(attribute:"plugin_publication_date", value: "2004/06/25");
 script_cvs_date("$Date: 2013/01/25 01:19:07 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "IIS Download.Ject Trojan Detection";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
 script_family(english: "Backdoors");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/iis"); 
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

sig = get_http_banner(port: port);
if (sig && "IIS" >!< sig)
  exit(0, "The web server on port "+port+" is not IIS.");

r = http_get_cache(item:"/", port:port, exit_on_fail: 1);

if ( ("function sc088(n24,v8)" >< r) &&
     ("var qxco7=document.cookie" >< r) )
{
	security_hole(port);
	exit(0);
}

