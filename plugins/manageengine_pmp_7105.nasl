#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80960);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/26 14:44:46 $");

  script_cve_id("CVE-2014-8499");
  script_bugtraq_id(71018);
  script_osvdb_id(114484,114485);

  script_name(english:"ManageEngine Password Manager Pro 6.5 < 7.1 Build 7105 Blind SQL Injection");
  script_summary(english:"Checks version of ManageEngine Password Manager Pro");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application affected by a SQL
injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of ManageEngine Password Manager
Pro between 6.5 (inclusive) and 7.1 Build 7105. It is, therefore,
affected by a blind SQL injection vulnerability due to a failure to
validate the 'SEARCH_ALL' parameter.");
  script_set_attribute(attribute:"see_also", value:"http://packetstormsecurity.com/files/129036");
  # http://www.manageengine.com/products/passwordmanagerpro/release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6b35a1c6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine Password Manager Pro version 7.1 build 7105 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:manageengine:password_manager_pro");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("manageengine_pmp_detect.nbin");
  script_require_keys("installed_sw/ManageEngine Password Manager Pro");
  script_require_ports("Services/www", 7272);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("http_func.inc");

appname = "ManageEngine Password Manager Pro";
# Stops get_http_port from branching
get_install_count(app_name:appname, exit_if_zero:TRUE);

port    = get_http_port(default:7272);
install = get_single_install(app_name:appname,port:port,exit_if_unknown_ver:TRUE);
version = install['version'];
build   = install['build'  ];
url     = install['path'   ];
url     = build_url(port:port,qs:url);

if (
  (version =~ "^6\." && ver_compare(ver:version,fix:"6.5",strict:FALSE) >= 0)
  ||
  # Build for 7.1 Build 7105+ is reliable
  (version =~ "^7\." && int(build) < 7105)
)
{
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  if (report_verbosity > 0)
  {
    report = '\n  URL               : ' + url +
             '\n  Installed version : ' + version +
             '\n  Build (at least)  : ' + build +
             '\n  Fixed version     : 7.1 Build 7105\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url,  version+" (at least build "+build+")");
