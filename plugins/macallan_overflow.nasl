#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(16153);
 script_bugtraq_id(12136);
 script_version ("$Revision: 1.14 $");
 script_osvdb_id(12674);
 script_xref(name:"Secunia", value:"13710");

 script_name(english:"Macallan Mail Solution Web Interface Authentication Bypass");
 script_summary(english:"Checks for Macallan Mail Solution version");
 
 script_set_attribute( attribute:"synopsis", value:
"A web application on the remote host has an authentication
bypass vulnerability." );
 script_set_attribute( attribute:"description",  value:
"The remote host is running Macallan Mail Solution, a mail server
(POP,SMTP,HTTP) for Windows.

It is possible to bypass web authentication by using two slashes
before the requested resource.  According to the vendor, this cannot
be used to perform administrative actions."  );
 # http://web.archive.org/web/20061224162100/http://cirt.dk/advisories/cirt-27-advisory.pdf
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?b3babc9f"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to version 4.1.1.0 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/12/31");
 script_cvs_date("$Date: 2013/12/19 23:04:05 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8080);
 script_exclude_keys("Settings/disable_cgi_scanning");

 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080);

foreach d ( cgi_dirs() )
{
 url = string(d, "/%2f/admin.html");
 res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: 1);

 if (egrep(pattern:"<title>Macallan Mail Solutions - Administration</title>", string:res[2]))
 {
   security_warning(port);
   exit(0);
 }
}
