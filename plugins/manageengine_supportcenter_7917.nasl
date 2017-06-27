#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72257);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/20 14:12:05 $");

  script_bugtraq_id(65199);
  script_xref(name:"OSVDB", value:"102656");
  script_xref(name:"EDB-ID", value:"31262");

  script_name(english:"ManageEngine SupportCenter Plus < 7.9 Build 7917 attach Parameter Directory Traversal");
  script_summary(english:"Checks version of ManageEngine SupportCenter Plus");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running a web application affected by a directory
traversal vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of ManageEngine SupportCenter Plus
prior to version 7.9 build 7917.  It is, therefore, affected by a
directory traversal vulnerability related to 'WorkOrder.do' and
attachments that could allow an attacker to download sensitive files."
  );
  script_set_attribute(attribute:"see_also", value:"https://supportcenter.wiki.zoho.com/ReadMe-V2.html#7917");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine SupportCenter version 7.9 build 7917 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:manageengine:supportcenter_plus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("manageengine_supportcenter_detect.nasl");
  script_require_keys("www/manageengine_supportcenter");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8080);
appname = 'ManageEngine SupportCenter Plus';

install = get_install_from_kb(appname:'manageengine_supportcenter', port:port, exit_on_fail:TRUE);
dir = install['dir'];
install_url = build_url(qs:dir, port:port);
ver_ui = install['ver'];

item = eregmatch(pattern:"^([0-9\.]+) Build ([0-9]+)$", string:ver_ui);
if (isnull(item)) audit(AUDIT_UNKNOWN_WEB_APP_VER, appname, install_url);

build = int(item[2]);

ver = split(item[1], sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 7 ||
  (ver[0] == 7 && ver[1] < 9) ||
  (ver[0] == 7 && ver[1] == 9 && ver[2] < 1) ||
  (ver[0] == 7 && ver[1] == 9 && ver[2] == 1 && build < 7917)
)
{
  if (report_verbosity > 0)
  {
    report = '\n  URL               : ' + install_url +
             '\n  Installed version : ' + ver_ui +
             '\n  Fixed version     : 7.9 Build 7917\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, ver_ui);
