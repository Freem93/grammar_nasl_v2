#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(10514);
  script_version ("$Revision: 1.24 $");
  script_cve_id("CVE-2000-0835");
  script_bugtraq_id(1684);
  script_osvdb_id(413);
  
  script_name(english:"Sambar Server ISAPI Search Utility search.dll Arbitrary Directory Listing");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to an information disclosure flaw." );
 script_set_attribute(attribute:"description", value:
"The 'search.dll' CGI that comes with Sambar server can be used to 
obtain a listing of the remote web server directories even if they 
have a default page, such as index.html.

This allows an attacker to gain valuable information about the
directory structure of the remote host and could reveal the
presence of files that are not intended to be visible." );
 script_set_attribute(attribute:"solution", value:
"Disable the search.dll CGI, or upgrade to Sambar 4.4b4." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/09/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/09/15");
 script_cvs_date("$Date: 2012/06/22 21:40:28 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:sambar:sambar_server");
script_end_attributes();


 script_summary(english:"Checks the presence of search.dll");
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2000-2012 Tenable Network Security, Inc.");

 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/sambar");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if (get_kb_item("www/no404/" + port)) exit(0);

r = http_send_recv3(method: "GET", item:"/search.dll?query=%00&logic=AND", port:port);
if ("HTTP/1.1 200 " >< r[0] && 'A HREF="/' >< r[1]+r[2])
  security_warning(port);


