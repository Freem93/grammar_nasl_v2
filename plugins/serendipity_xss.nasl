#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15914);
 script_version("$Revision: 1.18 $");

 script_cve_id("CVE-2004-2525");
 script_bugtraq_id(11790);
 script_osvdb_id(12177);

 script_name(english:"Serendipity compat.php searchTerm Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
cross-site scripting flaw." );
 script_set_attribute(attribute:"description", value:
"The remote version of Serendipity is vulnerable to cross-site
scripting attacks due to a lack of sanity checks on the 'searchTerm'
parameter in the 'compat.php' script.  With a specially crafted URL,
an attacker can cause arbitrary code execution in a user's browser
resulting in a loss of integrity." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e47198ec" );
 script_set_attribute(attribute:"see_also", value:"http://www.s9y.org/5.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Serendipity 0.7.1 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/12/02");
 script_cvs_date("$Date: 2015/01/15 03:38:17 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:s9y:serendipity");
script_end_attributes();

 script_summary(english:"Checks for Serendipity XSS flaw");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("serendipity_detect.nasl", "cross_site_scripting.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/serendipity");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/serendipity"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 loc = matches[2];

 req = http_get(item:string(loc, "/index.php?serendipity%5Baction%5D=search&serendipity%5BsearchTerm%5D=%3Cscript%3Efoo%3C%2Fscript%3E"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if ( "<script>foo</script>" >< r)
 {
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
 }
}
