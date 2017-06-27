#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11621);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2003-0286");
 script_bugtraq_id(7549);
 script_osvdb_id(4638);

 script_name(english:"Snitz Forums 2000 register.asp Email Parameter SQL Injection");
 script_summary(english:"Determine if Snitz forums is vulnerable to a cmd exec flaw");

 script_set_attribute( attribute:"synopsis", value:
"The discussion forum running on the remote web server has a SQL
injection vulnerability." );
 script_set_attribute( attribute:"description",  value:
"The remote version of Snitz Forums 2000 is vulnerable to a SQL
injection attack.  The 'Email' parameter of 'register.asp' is not
sanitized before being used in a SQL query.  A remote attacker could
exploit this to execute arbitrary SQL queries." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/vulnwatch/2003/q2/69"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Snitz Forums 2000 version 3.4.03 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89);
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/05/12");
 script_cvs_date("$Date: 2016/11/17 15:15:44 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/ASP");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


data = "Refer=&Email=test%27example.org&Email2=&HideMail=0&ICQ=&YAHOO=&AIM=&Homepage=&Link1=&Link2=&Name=test&Password=test&Password-d=&Country=&Sig=&MEMBER_ID=&Submit1=Submit";

port = get_http_port(default:80);
if(!can_host_asp(port:port))exit(0);

foreach d ( cgi_dirs() )
{
 if (is_cgi_installed3(item:d + "/register.asp", port:port))
 {
   w = http_send_recv3(method:"POST", port: port, item: d+"/register.asp?mode=DoIt",
     add_headers: make_array("Referer", build_url(port: port, qs: d+"/register.asp")),	
     content_type: "application/x-www-form-urlencoded",
     data: data);
   if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
   res = strcat(w[0], w[1], '\r\n', w[2]);
   if (w[0] =~ "HTTP/1\.[01] 500" && "Microsoft OLE DB Provider for SQL Server" >< res)
   {
   security_hole(port);
   set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
   exit(0);
  }
 }
}
