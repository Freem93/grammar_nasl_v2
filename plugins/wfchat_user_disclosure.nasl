#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11688);
 script_version ("$Revision: 1.21 $");

 script_cve_id("CVE-2003-1540");
 script_bugtraq_id(7147);
 script_osvdb_id(59645);

 name["english"] = "WF-Chat User Account Disclosure";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that is prone to an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The WF-Chat allows an attacker to view information about registered
users by requesting the files '!nicks.txt' and '!pwds.txt'." );
 script_set_attribute(attribute:"see_also", value:"http://lists.insecure.org/lists/bugtraq/2003/Mar/0271.html" );
 script_set_attribute(attribute:"solution", value:
"Delete this CGI." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(200);
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/02");
 script_cvs_date("$Date: 2011/03/13 23:54:24 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 summary["english"] = "Checks for the presence of !pwds.txt";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "no404.nasl");
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

port = get_http_port(default:80, embedded: 0);
if (get_kb_item("www/no404/"+port)) exit(0);

dirs = list_uniq(make_list("/chat", cgi_dirs()));
foreach dir (dirs)
{
 w = http_send_recv3(method:"GET", item:dir + "/!pwds.txt", port:port);
 if (isnull(w)) exit(1, "The web server did not answer");

 
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:w[0]))
 {
  data = w[2];
  notme = egrep(pattern:"^[^ ].*$", string:data);
  if(notme == NULL ){
   w = http_send_recv3(method:"GET", item:dir + "/chatlog.txt", port:port);
   if (isnull(w)) exit(1, "The web server did not answer");
   res = strcat(w[0], w[1], '\r\n', w[2]);
   if(egrep(pattern:"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ .[0-9].*", string:res))
   {
   security_warning(port);
   exit(0);
   }
  }
 }
}
