#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(24260);
 script_version ("$Revision: 1.12 $");
 script_cvs_date("$Date: 2011/05/31 15:21:57 $");

 script_name(english:"HyperText Transfer Protocol (HTTP) Information");

 script_set_attribute(attribute:"synopsis", value:
"Some information about the remote HTTP configuration can be extracted." );
 script_set_attribute(attribute:"description", value:
"This test gives some information about the remote HTTP protocol - the
version used, whether HTTP Keep-Alive and HTTP pipelining are enabled,
etc... 

This test is informational only and does not denote any security
problem." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/01/30");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Determines the version of HTTP spoken by the remote host");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("dotnet_framework_handlers.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);


w = http_send_recv3(method:"GET", item:"/", version: 11, port: port);
if (isnull(w)) exit(0);

v = eregmatch(string: w[0], pattern: "^(HTTP/[0-9.]+)");
if (! isnull(v)) version = v[1];

w = http_send_recv3(method:"OPTIONS", item:"*", version: 11, port: port);
if (! isnull(w))
{
 line = egrep(pattern:"^Allow: ", string:w[1]);
 if ( line ) options = ereg_replace(pattern:"^Allow: ", string:chomp(line), replace:"");
 else options = "(Not implemented)";
}

w = http_send_recv3(method:"GET", item: "/", version: 11, port: port,
  add_headers: make_array("Connection", "Keep-Alive"));

if (! isnull(w))
{
 r = w[1]; headers = r;
 if ( egrep(pattern:"^Keep-Alive:", string:r) ||
      egrep(pattern:"^Connection: Keep-Alive", string:r) ) ka = "yes";
 else ka = "no";
}

report = '\n';
report += 'Protocol version : ' + version + '\n';
if ( get_port_transport(port) > ENCAPS_IP ) report += 'SSL : yes\n';
else report += 'SSL : no\n';
#if ( pipelining ) report += 'Pipelining : ' + pipelining + '\n';
if ( ka         ) report += 'Keep-Alive : ' + ka + '\n';
if ( options    ) report += 'Options allowed : ' + options + '\n';
if ( headers )
{
 headers_a  = split(headers, keep:FALSE);
 headers = NULL;
 foreach line ( headers_a )
	headers += '  ' + line + '\n';
	
 report += 'Headers :\n\n' + headers;
}

if ( ! report ) exit(0);
security_note(port:port, extra:report);
