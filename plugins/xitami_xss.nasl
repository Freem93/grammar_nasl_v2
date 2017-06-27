#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(13841);
 script_version ("$Revision: 1.14 $");
 script_bugtraq_id(10778);
 script_osvdb_id(54866);
 
 script_name(english:"Xitami testssi.ssi HTTP Header XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a script that is affected by a cross-
site scripting flaw." );
 script_set_attribute(attribute:"description", value:
"The remote Xitami server is distributed with a script for testing
server-side includes, '/testssi.ssi'.  This script is vulnerable to a
cross-site scripting issue when sent a request with a malformed Host
or User-Agent header.  An attacker may exploit this flaw the steal the
authentication credentials of third-party users." );
 script_set_attribute(attribute:"see_also", value:"http://www.oliverkarow.de/research/xitami25c1_testssi_XSS.txt" );
 script_set_attribute(attribute:"solution", value:
"Remove the test script '/testssi.ssi'." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/26");
 script_cvs_date("$Date: 2015/01/16 03:36:09 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Xitami XSS test");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
if ( ! thorough_tests && "Xitami" >!< banner ) exit(0);


r = http_send_recv3(method: "GET", port: port, item: "/", version: 11, 
  add_headers: make_array("User-Agent", "<script>foo</script>") );
if (isnull(r)) exit(0);

if ( "<script>foo</script>" >< r[2] )
{
 security_warning(port);
 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
 exit(0);
}
