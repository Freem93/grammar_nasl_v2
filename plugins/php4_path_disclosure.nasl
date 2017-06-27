#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(11008);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/03/02 14:34:38 $");

  script_cve_id("CVE-2002-0249");
  script_bugtraq_id(4056);
  script_osvdb_id(827);

  script_name(english:"Apache on Windows php.exe Malformed Request Path Disclosure");
  script_summary(english:"Tests for PHP Physical Path Disclosure Vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache running on the remote Windows host will reveal
the physical path of the PHP cgi binary when sent a specially crafted
HTTP GET request.");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=101311698909691&w=2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of PHP and Apache.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value: "2002/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value: "2002/06/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2002-2015 Tenable Network Security, Inc.");

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

cgi_list = make_list();

kb = get_kb_list('www/' + port + '/content/extensions/php');
if(!isnull(kb)) cgi_list = make_list(kb); # flattens array into list

test_list = make_list('/index.php');

limit = 1;
if (thorough_tests) limit = 10;

for (i=0; i<limit; i++)
{
  if(max_index(cgi_list) > i)
    test_list = make_list(test_list, cgi_list[i]);
  else break;
}

test_list = list_uniq(test_list);

foreach url (test_list)
{
  res = http_send_recv3(method       : "GET",
                        port         : port,
                        item         : url + "/123",
                        exit_on_fail : TRUE);

  item = eregmatch(pattern : "Premature end of script headers:[^\n\r]+/php(-cgi)?\.exe[\s\n]",
                   string  : res[2]);

  if(!isnull(item)) break;
}

if(!isnull(item))
{
  security_report_v4(
    port      : port,
    severity  : SECURITY_WARNING,
    generic   : TRUE,
    request   : make_list(build_url(port:port, qs:url+"/123")),
    output    : '\n' + item[0]
  );
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port);
