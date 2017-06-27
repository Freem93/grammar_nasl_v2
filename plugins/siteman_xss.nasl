#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(16171);
  script_version("$Revision: 1.18 $");
  
  script_bugtraq_id(12267);
  script_osvdb_id(12985);

  script_name(english:"Siteman forum.php page Parameter XSS");
  script_summary(english:"Checks Siteman XSS");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP application that is affected by
a cross-site scripting attack."  );
  script_set_attribute( attribute:"description",  value:
"The remote host is running Siteman, a web-based content management
system written in PHP.

The remote version of this software is vulnerable to a cross-site
scripting attack due to a lack of sanitization of user-supplied data
to the 'page' parameter of the 'forum.php' script.  Successful
exploitation of this issue may allow an attacker to use the remote
server to perform an attack against a third-party user."  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/bugtraq/2005/Jan/165"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Unknown at this time."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/14");
 script_cvs_date("$Date: 2016/11/17 15:28:26 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:siteman:siteman");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses : XSS");

  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("cross_site_scripting.nasl");
  script_require_keys("www/PHP");
  exit(0);
}

#the code

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if ( ! can_host_php(port:port) ) exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

foreach dir (cgi_dirs())
{
 w = http_send_recv3(method:"GET", item:dir + "/forum.php?do=viewtopic&cat=1&topic=1&page=1?<script>foo</script", port:port);
 if (isnull(w)) exit(1, "The web server did not answer");
 r = w[2];

 if(egrep(pattern:"a class=.cal_head. href=.*<script>foo</script>", string:r))
 {
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
 }
}
