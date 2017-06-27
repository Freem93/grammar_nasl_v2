#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(13842);
 script_bugtraq_id(10774);
 script_xref(name:"Secunia", value:"12155");
 script_version ("$Revision: 1.11 $");

 script_name(english:"Mensajeitor Tag Board Admin Bypass");
 script_summary(english:"Mensajeitor test");
 
 script_set_attribute( attribute:"synopsis", value:
"A web application running on the remote host has a security bypass
vulnerability." );
 script_set_attribute(attribute:"description",  value:
"The remote host is running Mensajeitor Tag Board.

According to its banner, the remote version of Mensajeitor has
a security bypass vulnerability.  Admin authentication can be
bypassed by passing a value 'si' to the 'AdminNick' parameter.
A remote attacker could exploit this issue to post messages with
administrative privileges." );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Mensajeitor 1.8.9 r2 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/26");
 script_cvs_date("$Date: 2011/03/14 21:48:07 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if ( ! banner ) exit(1, "No HTTP banner on port "+port+".");

foreach dir ( cgi_dirs() )
{
 url = dir + "/mensajeitor.php";
 res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: 1);

 if ( "Mensajeitor" >< res[2] && egrep(pattern:"<title>Mensajeitor v1\.([0-7]\.|8\.[0-9])</title>", string:res[2]))
	{
	 security_warning(port);
	 exit(0);
	}

}
