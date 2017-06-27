#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if (description)
{
  script_id(18048);
  script_cve_id("CVE-2005-1135");
  script_bugtraq_id(13170);
  script_osvdb_id(15846);
  script_version ("$Revision: 1.19 $");

  script_name(english:"sphpblog search.php q Parameter XSS");
  script_summary(english:"Determine if sphpblog is vulnerable to xss attack");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote web application is vulnerable to an injection attack.'
  );

  script_set_attribute(
    attribute:'description',
    value:'Due to a lack of input validation, the remote version of Simple PHP
Blog can be used to perform a cross-site scripting attack by
injecting arbitrary script code to the \'q\' parameter of the
search.php script.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Upgrade to a newer version or disable this software.'
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(
    attribute:'see_also',
    value:'http://seclists.org/bugtraq/2005/Apr/232'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/14");
 script_cvs_date("$Date: 2016/12/14 20:33:26 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_dependencie("sphpblog_detect.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/sphpblog");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/sphpblog"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
 d = matches[2];
 url = string(d, "/search.php?q=<script>foo</script>");
 w = http_send_recv3(method:"GET", item:url, port:port);
 if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
 buf = w[2];
 if("<b><script>foo</script></b>" >< buf )
   {
    security_warning(port:port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
   }
}
