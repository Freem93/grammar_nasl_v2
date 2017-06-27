#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10143);
 script_version ("$Revision: 1.35 $");

 script_cve_id("CVE-1999-0753");
 script_bugtraq_id(591);
 script_osvdb_id(1049);

 script_name(english:"Mini SQL w3-msql Arbitrary Directory Access");
 script_summary(english:"Overflows the remote CGI buffer");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected
by an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote web server appears to be running w3-msql. The installed 
version allows a malicious user to view restricted directories with
specially crafted requests." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1999/Aug/185" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
	
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/09/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/08/18");
 script_cvs_date("$Date: 2016/10/27 15:03:55 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

foreach dir (cgi_dirs())
{
 if(!ereg(pattern:".*\.nsf/.*", string:dir))
 {
   res = http_send_recv3(method:"GET", item:string(dir, "/w3-msql/"), port:port);
   if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

   res[2] = tolower(res[2]);
   if ("internal server error" >< res[2]) exit(0);

   res = http_send_recv3(method:"GET", item:string(dir, "/w3-msql/", crap(250)), port:port);
   if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

   res[2] = tolower(res[2]);
   if ("internal server error" >< res[2] &&
       !egrep(string:res[2], pattern:"w3-msql.* not found"))
   {
     security_hole(port);
     exit(0);
   }
  }
}
