#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14180);
 script_version("$Revision: 1.13 $");
 script_cve_id("CVE-2004-2061");
 script_bugtraq_id(10812);
 script_osvdb_id(8265);

 script_name(english:"RiSearch show.pl Open Proxy Relay");

 script_set_attribute(attribute:"synopsis", value:
"The remote server may be used as an anonymous proxy." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running RiSearch, a local search engine.

There is a flaw in the CGI 'show.pl' which is bundled with this software
that could allow an attacker to use the remote host as an open proxy by 
doing a request like :

http://www.example.com/cgi-bin/search/show.pl?url=http://www.google.com

An attacker could exploit this flaw to use the remote host as a proxy,
and therefore to connect anonymously to the internet." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/07/27");
 script_cvs_date("$Date: 2011/12/15 22:14:32 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Determines the presence of RiSearch's search.pl");
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencies("http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

foreach dir ( cgi_dirs() )
{
 r = http_send_recv3(port:port, method: "GET", item:dir + "/search/show.pl?url=http://www.google.com");
 if (isnull(r)) exit(0);
 if ("<title>Google</title>" >< r[2] && "I'm Feeling Lucky" >< r[2]) 
 {
   security_hole(port);
   exit(0);
 }
}
