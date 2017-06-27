#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(16322);
  script_version ("$Revision: 1.15 $");
  script_bugtraq_id(12438);
  script_osvdb_id(13450);

  script_name(english:"SunShop Shopping Cart index.php search Parameter XSS");
  script_summary(english:"Checks if SunShop Shopping Cart is installed");

   script_set_attribute(
    attribute:'synopsis',
    value:'The remote web application is vulnerable to cross-site scripting.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote host is running SunShop, a web-based shopping cart
program written in PHP.

The remote version of this software is vulnerable to several input
validation flaws, which may allow an attacker to use the remote web
site to perform a cross-site scripting attack.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Upgrade to SunShop version 3.5 or later.'
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.nessus.org/u?82d003ec'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/03");
 script_cvs_date("$Date: 2016/12/14 20:33:27 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

# The script code starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)) exit(0);

foreach dir ( cgi_dirs() )
{
 w = http_send_recv3(method:"GET", item:dir + "/index.php?search=<script>foo</script>", port:port);
 if (isnull(w)) exit(1, "The web server did not answer");
 res = strcat(w[0], w[1], '\r\n', w[2]);
 if('<input type="text" name="search" size="10" class="input_box" value="<script>foo</script>">' >< res )
  {
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
  }
}
