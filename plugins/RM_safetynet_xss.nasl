#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(18182);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/06/02 14:01:26 $");

  script_osvdb_id(15543);
  
  script_name(english:"RM SafetyNet Plus snpfiltered.pl u Parameter XSS");
  script_summary(english:"Checks RM SafetyNet Plus XSS");

  script_set_attribute(
    attribute:"synopsis",
    value:"A web filtering application has a cross-site vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running SafetyNet Plus, an educational web
filtering application.

This version is vulnerable to a cross-site scripting attack.  Input
to the 'u' parameter of snpfiltered.pl is not properly sanitized.  A
remote attacker could exploit this by tricking a user into requesting
a maliciously crafted URL."
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to the latest version of this application."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/02");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/12");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses : XSS");

  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  exit(0);
}

#the code

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

function check(req)
{
  local_var buf, r;
  buf = http_get(item:string(req,"/snpfiltered.pl?t=c&u=<script>foo</script>"), port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);

  if (ereg(pattern:"RM SafetyNet Plus</title>", string:r, icase:1) && ("<script>foo</script>" >< r))
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}

foreach dir (cgi_dirs())
{
    check(req:dir);
}
