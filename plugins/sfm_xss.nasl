#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11362);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2003-1539");
 script_bugtraq_id(7035);
 script_osvdb_id(54765);

 script_name(english: "Simple File Manager Directory / Filename XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"A CGI script on the remote web server is vulnerable to an XSS attack." );
 script_set_attribute(attribute:"description", value:
"The remote Simple File Manager CGI (fm.php) improperly validates 
the names of the directories entered and created by the user.

As a result, a user could generate a cross-site scripting attack
on this host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SFM 0.21 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);


 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/12");
 script_cvs_date("$Date: 2011/03/14 21:48:12 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();
 
 script_summary(english: "Checks for the version of fm.php");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses : XSS");
 script_dependencie("find_service1.nasl", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port))exit(0);


foreach dir (make_list(cgi_dirs(), "/sfm"))
{
 r = http_send_recv3(port: port, method: "GET", item: strcat(dir, "/fm.php"));
 if (isnull(r)) exit(0);

 str = egrep(pattern:"simple file manager", string:r[2], icase:TRUE);
 if(str)
 {
  if(ereg(string:str, pattern:".*class=tiny> \.0(0[0-9]|1[0-9]|20)[^0-9]"))
   {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
   }
 }
}
