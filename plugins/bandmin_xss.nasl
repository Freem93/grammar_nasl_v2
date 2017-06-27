#
# (C) Tenable Network Security, Inc.
#

#
# Date: 28 May 2003 16:38:40 -0000
# From: silent needel <silentneedle@hotmail.com>
# To: bugtraq@securityfocus.com
# Subject: Bandmin 1.4 XSS Exploit



include("compat.inc");

if(description)
{
 script_id(11672);
 script_version ("$Revision: 1.26 $");
 script_cve_id("CVE-2003-0416");
 script_bugtraq_id(7729);
 script_osvdb_id(4788);

 script_name(english:"Bandmin 1.4 index.cgi Multiple Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a CGI script that is vulnerable to a
cross-site scripting issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Bandmin CGI suite. 

There is a cross-site scripting issue in this suite that may allow an
attacker to steal your users cookies. 

The flaw lies in the cgi bandwitdh/index.cgi" );
 script_set_attribute(attribute:"solution", value:
"None at this time.  You are advised to remove this CGI." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/05/28");
 script_cvs_date("$Date: 2015/01/13 06:57:51 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 script_summary(english:"Checks for Bandmin");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("http_version.nasl", "no404.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# The script code starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

foreach d (make_list(  cgi_dirs()))
{
 r = http_send_recv3(port: port, method: 'GET', 
 item:string(d, "/bandwidth/index.cgi?action=showmonth&year=<script>foo</script>&month=<script>foo</script>"));
 if (isnull(r)) exit(0);
 if(r[0] =~ "^HTTP/[0-9]\.[0-9] +200 " &&
    egrep(pattern:"<script>foo</script>", string: r[2])) {
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
 }
}
