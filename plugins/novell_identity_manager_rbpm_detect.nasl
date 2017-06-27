#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65916);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/01/08 00:57:14 $");

  script_name(english:"Novell Identity Manager Role Based Provisioning Module Detection");
  script_summary(english:"Detects Novell Identity Manager Role Based Provisioning Module");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web interface for an identity management solution was detected on
the remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The web interface for Novell Identity Manager Role Based Provisioning
Module was detected on the remote host. Novell Identity Manager is an
enterprise identity management solution."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.netiq.com/products/identity-manager/advanced/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:identity_manager_roles_based_provisioning_module");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8180);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname_audit = "Novell Identity Manager Role Based Provisioning Module";
appname = "novell_identity_management_rbpm";

port = get_http_port(default:8180, embedded:FALSE);
base_kb = "www/" + port + "/" + appname + "/";

res = http_send_recv3(item:"/IDMProv/jsps/help/Help.jsp",
                      port:port,
                      method:"GET",
                      exit_on_fail:TRUE);

installs = NULL;

if (
  "Identity Manager Roles Based Provisioning Module" >< res[2] &&
  "<title>Identity Manager" >< res[2]
)
{
  version = UNKNOWN_VER;

  #>Identity Manager Roles Based Provisioning Module Version 4.0.2 Patch C</div>
  item = eregmatch(pattern:'>Identity Manager Roles Based Provisioning Module Version[ ]*([^<]+)',
                   string: res[2]);
  if (!isnull(item)) version = item[1];

  #>Build Revision 39446</div>
  item = eregmatch(pattern:'>Build Revision[ ]*([0-9]+)<',
                   string: res[2]);
  if (!isnull(item)) set_kb_item(name:base_kb + 'build', value:item[1]);

  installs = add_install(
    installs:installs,
    dir:'/IDMProv',
    appname:appname,
    port:port,
    ver:version
  );
}

if (!isnull(installs))
{
  if (report_verbosity > 0)
  {
    report = get_install_report(
      display_name:appname,
      installs:installs,
      port:port
    );
    security_note(extra:report, port:port);
  }
  else security_note(port);
}
else audit(AUDIT_WEB_APP_NOT_INST, appname_audit, port);
