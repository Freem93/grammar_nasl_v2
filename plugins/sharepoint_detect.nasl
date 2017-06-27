#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(38157);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/08/09 00:11:25 $");

  script_name(english:"Microsoft SharePoint Server Detection");
  script_summary(english:"Detects a SharePoint Server");

 script_set_attribute(attribute:"synopsis", value:"The remote web server contains a document sharing software");

 script_set_attribute(attribute:"description", value:
"The remote web server is running SharePoint,  a web interface for
document management.

As this interface is likely to contain sensitive information, make sure
only authorized personel can log into this site");
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/Sharepoint/default.mspx");
 script_set_attribute(attribute:"solution", value:"Make sure the proper access controls are put in place");

  script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443);
  script_require_keys("www/ASP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443, asp:TRUE);

res = http_get_cache(item:"/", port:port, exit_on_fail:TRUE);

if ( (line = egrep(pattern:"^MicrosoftSharePointTeamServices: ", string:res)) )
{
 version = ereg_replace(pattern:"^MicrosoftSharePointTeamServices: ([0-9.]+).*", string:line, replace:"\1");
 installs = add_install(dir:'', ver:version, appname:'sharepoint', port:port);
 report = get_install_report(display_name:'SharePoint', installs:installs, port:port);
 security_note(port:port, extra:report);
}

