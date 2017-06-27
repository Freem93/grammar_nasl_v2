#
# (C) Tenable Network Security, Inc.
#
# References:
#
# From:Stefan.Bagdohn@guardeonic.com
# To: bugtraq@securityfocus.com
# Subject: Advisory: TCP-Connection risk in DB4Web 
# Date: Tue, 17 Sep 2002 14:44:17 +0200
#


include("compat.inc");

if(description)
{
 script_id(11180);
 script_cve_id("CVE-2002-1484");
 script_bugtraq_id(5725);
 script_osvdb_id(14485);
 script_xref(name:"Secunia", value:"7119");

 script_version ("$Revision: 1.14 $");
  
 script_name(english:"DB4Web Server Debug Mode TCP Port Scanning Proxy");
 script_summary(english:"DB4Web debug page allow bounce scan");
 
 script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host has an information
disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The DB4Web debug page allows anybody to scan other machines.
This could allow a remote attacker to learn more about the internal
network layout, which could be used to mount further attacks." );
 # https://web.archive.org/web/20031216120958/http://archives.neohapsis.com/archives/vulnwatch/2002-q3/0125.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29b846de" );
 script_set_attribute(attribute:"solution", value:
"Replace the debug page with a non-verbose error page." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/12/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/09/17");
 script_cvs_date("$Date: 2016/10/10 15:57:04 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# testhost = "nosuchwww.example.com";
testhost = this_host_name();

u =  string("/DB4Web/", testhost, ":23/foo");
r = http_send_recv3(port:port, method: "GET", item: u);

c = strcat(r[0], r[1], '\r\n', r[2]);
if ((("connect() ok" >< c) || ("connect() failed:" >< c)) &&
    ("callmethodbinary_2 failed" >< c))
  security_warning(port);
