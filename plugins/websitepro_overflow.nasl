#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10476);
 script_bugtraq_id(1492);
 script_osvdb_id(375);
 script_cve_id("CVE-2000-0623");
 script_version ("$Revision: 1.27 $");
 
 script_name(english:"WebsitePro Remote Request Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by remote buffer overflows." );
 script_set_attribute(attribute:"description", value:
"The remote web server is WebSitePro < 2.5.

There are remotely-exploitable buffer overflow vulnerabilities in
releases of WebSitePro prior to 2.5." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Jul/271");
 script_set_attribute(attribute:"solution", value:
"Upgrade to WebSitePro 2.5 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/07/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/07/19");
 script_cvs_date("$Date: 2016/11/03 14:16:37 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 
 summary["english"] = "Checks for WebSitePro";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/websitepro");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);

if(banner)
{
  if(egrep(pattern:"Server: WebSitePro/2\.[0-4].*", string:banner))
     security_hole(port);
}

