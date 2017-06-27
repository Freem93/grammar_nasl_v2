#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65917);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/01/08 00:57:14 $");

  script_cve_id("CVE-2013-1083");
  script_bugtraq_id(58786);
  script_osvdb_id(91837);

  script_name(english:"Novell Identity Manager Role Based Provisioning Module Unspecified Vulnerability");
  script_summary(english:"Checks version of Novell Identity Manager Role Based Provisioning Module");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server has an application with an unspecified
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server has an install of Novell Identity Manager Role
Based Provisioning Module that is affected by an unspecified
vulnerability in its login functionality."
  );
  script_set_attribute(attribute:"see_also", value:"http://download.novell.com/Download?buildid=nbGXg-msbmw~");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply Novell Identity Manager Roles Based Provisioning Module 4.0.2
Field Patch C."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:identity_manager_roles_based_provisioning_module");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("novell_identity_manager_rbpm_detect.nasl");
  script_require_keys("www/novell_identity_management_rbpm");
  script_require_ports("Services/www", 8180);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8180);
appname_audit = "Novell Identity Manager Role Based Provisioning Module";
appname = "novell_identity_management_rbpm";
base_kb = "www/" + port + "/" + appname + "/";

install = get_install_from_kb(appname:appname, port:port, exit_on_fail:TRUE);
build = get_kb_item_or_exit(base_kb + "build");

dir = install['dir'];
version = install['ver'];
location = build_url(qs:dir, port:port);

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, appname_audit, location);

# only 4.0.2 affected
if (
  version =~ "^4\.0\.2($|[^0-9])" &&
  build < 39446
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + location +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.0.2 Patch C' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname_audit, location, version);
