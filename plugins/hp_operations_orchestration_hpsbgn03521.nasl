#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87172);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/28 18:42:40 $");

  script_cve_id("CVE-2015-5451");
  script_bugtraq_id(77632);
  script_osvdb_id(130437);
  script_xref(name:"HP", value:"HPSBGN03521");
  script_xref(name:"HP", value:"SSRT102923");
  script_xref(name:"HP", value:"emr_na-c04894110");

  script_name(english:"HP Operations Orchestration 10.x < 10.22.001 XSRF");
  script_summary(english:"Checks the HP Operations Orchestration version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an unspecified cross-site request
forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP Operations Orchestration installed on the remote
host is 10.x prior to 10.22.001. It is, therefore, affected by a
unspecified cross-site request forgery (XSRF) vulnerability. A remote
attacker can exploit this, by tricking a user into following a
specially crafted link, to upload arbitrary code or hijack the user
authentication.

Note: Per the vendor advisory, if a user has a version installed 
prior to 10.22, and they apply the 10.50 patch, the CSRF setting 
will be automatically enabled. If the user has the 10.22 patch, 
then they have to manually enable the CSRF protection setting.");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04894110
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc605c10");
  # https://softwaresupport.hp.com/group/softwaresupport/search-result/-/facetsearch/document/KM01858399
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?780b4522");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP Operations Orchestration version 10.22.001 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:operations_orchestration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_operations_orchestration_detect.nbin");
  script_require_ports("Services/www", 8080, 8443);
  script_require_keys("installed_sw/HP Operations Orchestration");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

appname = "HP Operations Orchestration";

get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:8080);

install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);

dir = install['path'];
version = install['version'];

install_url = build_url(port:port, qs:dir);

if (version =~ '^10\\.' && ver_compare(ver:version, fix:"10.22.001", strict:FALSE) < 0)
{
  set_kb_item(name: 'www/'+port+'/XSRF', value: TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 10.22.001\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port:port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, version);
