#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(18038);
  script_version("$Revision: 1.16 $");
  script_cve_id("CVE-2005-1130");
  script_bugtraq_id(13138);
  script_xref(name:"OSVDB", value:"15485");

  script_name(english:"Pinnacle Cart index.php pg Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web application is vulnerable to cross-site scripting." );
 script_set_attribute(attribute:"description", value:
"The remote host runs Pinnacle Cart, a shopping cart software written
in PHP.

The remote version of this software is vulnerable to cross-site
scripting attacks due to a lack of sanity checks on the 'pg' parameter
in the script 'index.php'." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Pinnacle Cart 3.3 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/13");
 script_cvs_date("$Date: 2017/02/23 16:41:18 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_summary(english:"Checks XSS in Pinnacle Cart");
  script_category(ACT_ATTACK);
  
  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses : XSS");
  script_dependencie("cross_site_scripting.nasl"); 
  script_require_ports("Services/www", 80);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

test_cgi_xss( port: port, cgi: "index.php", 
 qs: "p=catalog&parent=42&pg=<script>foo</script>",
 pass_re: '<input type="hidden" name="backurl" value=".*/index\\.php?p=catalog&parent=42&pg=<script>foo</script>');
