#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(10670);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/11/02 14:37:08 $");

  script_osvdb_id(555);

  script_name(english:"PHP3 Physical Path Disclosure via POST Requests");
  script_summary(english:"Tests for PHP Physical Path Disclosure Vulnerability.");

  script_set_attribute(attribute:"synopsis",value:
"The remote server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description",value:
"The version of PHP3 running on the remote host will reveal the
physical path of a given script when sent a HTTP POST request without
a content-type header if it is incorrectly configured.");
  script_set_attribute(attribute:"see_also",value:"http://seclists.org/bugtraq/2000/Jun/226");
  script_set_attribute(attribute:"solution",value:
"In the PHP configuration file, change display_errors to 'Off' or
upgrade to an unaffected PHP version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date",value:"2001/05/14");
  script_set_attribute(attribute:"plugin_publication_date",value:"2015/02/27");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");

  exit(0);
}
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

version = php["ver"];

if(version !~ "^3\.")
  audit(AUDIT_NOT_DETECT, "PHP version 3.x", port);

kb = get_kb_list('www/' + port + '/content/extensions/php');
if(!isnull(kb)) cgi1_list = make_list(kb); # flattens array into list
kb = get_kb_list('www/' + port + '/content/extensions/php3');
if(!isnull(kb)) cgi2_list = make_list(kb);

test_list = make_list('/index.php', '/index.php3');

limit = 1;
if (thorough_tests) limit = 10;

for (i=0; i<limit; i++)
{
  if(max_index(cgi1_list) < i && max_index(cgi2_list) < i) break;
  if(max_index(cgi1_list) > i)
    test_list = make_list(test_list, cgi1_list[i]);
  if(max_index(cgi2_list) > i)
    test_list = make_list(test_list, cgi2_list[i]);
}

test_list = list_uniq(test_list);

foreach url (test_list)
{
  res = http_send_recv3(method       : "POST",
                        port         : port,
                        item         : url,
                        exit_on_fail : TRUE);

  item = eregmatch(pattern : "<b>Warning</b>:\s*POST Error: content-type missing in\s*<b>[^<]+</b>",
                   string  : res[2]);

  if(!isnull(item)) break;
}

if(!isnull(item))
{
  security_report_v4(
    port      : port,
    severity  : SECURITY_WARNING,
    generic   : TRUE,
    request   : make_list(chomp(http_last_sent_request())),
    output    : '\n' + item[0]
  );
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP3.x", port);
