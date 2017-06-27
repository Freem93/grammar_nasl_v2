#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(11527);
 script_version ("$Revision: 1.30 $");

 script_cve_id("CVE-2002-0316", "CVE-2003-0375", "CVE-2003-0483");
 script_bugtraq_id(4167, 4944, 8013);
 script_osvdb_id(2191, 8874, 23073);
 script_xref(name:"EDB-ID", value:"21300");

 script_name(english:"XMB < 1.9.1 Multiple XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains several PHP scripts that are prone to
cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running XMB Forum, a web forum written in PHP.

The version of XMB installed on the remote host is affected by several
cross-site scripting issues." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=101447886404876&w=2" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27b51f87" );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=105638720409307&w=2" );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=105363936402228&w=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to XMB 1.9.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/04/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/06/23");
 script_cvs_date("$Date: 2015/11/18 21:03:58 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Determine if XMB forums is vulnerable to xss attack");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if(!can_host_php(port:port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);


xss = '<script>x</script>';
if (thorough_tests){
  dirs = list_uniq(make_list("/xmb", "/forum", "/forums", "/board", cgi_dirs()));
  exploits = make_list(
    string('/forumdisplay.php?fid=21">', xss),
    string('/buddy.php?action=', xss),
    string('/admin.php?action=viewpro&member=admin', xss)
  );
} 
else {
  dirs = make_list(cgi_dirs());
  exploits = make_list(
    string('/forumdisplay.php?fid=21">', xss)
  );
}

foreach dir (dirs) {
 foreach exploit (exploits) {
  url = string(dir, exploit);
  r = http_send_recv3(method: "GET", item:url, port:port);
  if( isnull(r) ) exit(0);
  buf = r[2];
  if (
   (
    "Powered by X M B" >< buf ||
    "Powered by XMB" >< buf 
   ) && 
   xss >< buf
  ) {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
   exit(0);
  }
 }
}
