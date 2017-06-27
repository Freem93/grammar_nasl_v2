#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15717);
 script_version("$Revision: 1.24 $");

 script_cve_id("CVE-2004-2245", "CVE-2004-2246");
 script_bugtraq_id(11587);
 script_osvdb_id(11318, 11319, 11320, 11624);
 
 script_name(english:"Goollery < 0.04b Multiple Vulnerabilities");
 script_summary(english:"Checks fot the presence of Goollery XSS flaw in viewpic.php");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
a cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of
Goollery running on the remote host is affected by multiple cross-site
scripting (XSS) vulnerabilities in the viewpic.php script. An
unauthenticated, remote attacker can exploit these vulnerabilities,
via a specially crafted request, to execute arbitrary script code in a
user's browser session." );
 script_set_attribute(attribute:"see_also", value:"http://osvdb.org/ref/11/11xxx-goollery_multiple.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Goollery 0.04b or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:U/RC:X");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/11/01");
 script_cvs_date("$Date: 2016/12/22 14:57:57 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP", "Settings/ParanoidReport");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if ( get_kb_item("www/" + port + "/generic_xss") )
 exit(0, "The web server on port "+port+" is prone to XSS.");
if(!can_host_php(port:port))
 exit(0, "The web server on port "+port+" does not support PHP.");

function check(loc)
{
  local_var r, url;

  url = loc + '/viewpic.php?id=7&conversation_id=<script>foo</script>&btopage=0';
  r = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);
  if(
    egrep(pattern:"^HTTP/1\.[01] +200 ", string:r[0]) && 
    egrep(pattern:"<script>foo</script>", string:r[2])
  )
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}

dir = make_list(cgi_dirs(),"/goollery");
foreach d (dir)	
{
 	check(loc:d);
}
