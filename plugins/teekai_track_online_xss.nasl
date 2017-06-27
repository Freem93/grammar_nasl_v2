#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15707);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2002-2055");
  script_bugtraq_id(4924);
  script_osvdb_id(4163);
  
  script_name(english:"TeeKai Tracking Online XSS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web applicaton on the remote host has a cross-site scripting
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host runs Teekai Tracking Online, a PHP script used
for tracking the number of users on a Web site.  This version is
vulnerable to cross-site scripting attacks.  A remote attacker could
exploit this by tricking a user into requesting a maliciously crafted
URL, resulting in the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/vuln-dev/2002/Jun/30"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to the latest version of this software."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/13");
 script_cvs_date("$Date: 2016/11/17 15:15:44 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_summary(english:"Checks XSS in TeeKai Tracking Online");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses : XSS");
  script_dependencies("cross_site_scripting.nasl");
  script_require_ports("Services/www");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);
if ( get_kb_item("www/" + port + "/generic_xss" ) ) exit(0);

if(get_port_state(port))
{
 url = "/page.php?action=view&id=1<script>foo</script>";
 r = http_send_recv3(method:"GET", port:port, item:url);
 if(isnull(r)) exit(1, "The web server on port "+port+" failed to respond.");
 if(
  "<script>foo</script>" >< r[2] &&
  egrep(pattern:"^HTTP/1\.[01] +200 ", string:r[2])
 )
 {
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
 }
}

