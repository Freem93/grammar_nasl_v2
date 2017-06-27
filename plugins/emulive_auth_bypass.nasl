#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(14805);
 script_cve_id("CVE-2004-1695", "CVE-2004-1696");
 script_bugtraq_id(11226);
 script_osvdb_id(10176, 10177);
 script_version ("$Revision: 1.11 $");

 script_name(english:"Emulive Server4 Authentication Bypass");
 script_summary(english:"Requests the admin page of the remote EmuLive Server4");
 
 script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host has an authentication
bypass vulnerability." );
 script_set_attribute(attribute:"description",  value:
"The remote host is running EmuLive Server4, a web and media streaming
server.

There is a flaw in the administrative interface that allows a remote
attacker to bypass the authentication procedure by requesting the page
'/public/admin/index.htm' directly.

An attacker may exploit this flaw to gain administrative access over
the remote service.

Emulive has also been reported to have a denial of service condition
when handling carriage returns, though Nessus has not checked for this
issue." );
 script_set_attribute( attribute:"see_also",
   value:"http://seclists.org/bugtraq/2004/Sep/266"
 );
 script_set_attribute(attribute:"solution", 
   value:"Upgrade to the latest version of this software."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/20");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
		
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 81);

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:81);
res = http_send_recv3(method:"GET", item:"/PUBLIC/ADMIN/INDEX.HTM", port:port);
if (isnull(res)) exit(0);

if (
  "Emulive Server4" >< res[2] &&
  "<title>Server4 Administration Console</title>" >< res[2]
) security_hole(port);
