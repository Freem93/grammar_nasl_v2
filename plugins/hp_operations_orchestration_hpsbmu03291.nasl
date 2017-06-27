#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83348);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/21 22:04:46 $");

  script_cve_id("CVE-2015-2108");
  script_bugtraq_id(73320);
  script_osvdb_id(119906);
  script_xref(name:"HP", value:"HPSBMU03291");
  script_xref(name:"HP", value:"SSRT101980");
  script_xref(name:"HP", value:"emr_na-c04595417");

  script_name(english:"HP Operations Orchestration 10.x Remote Information Disclosure");
  script_summary(english:"Checks the HP Operations Orchestration version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by remote information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of HP Operations Orchestration installed
that is 10.x prior to 10.21.0001. It is, therefore, affected by an
information disclosure vulnerability. A remote, authenticated attacker
can exploit this, via PowerShell (PS) script operations, to obtain
user passwords and other sensitive information.");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04595417
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9b08cfad");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP Operations Orchestration 10.21.0001 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/12");

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

port = get_http_port(default:8080);
appname = "HP Operations Orchestration";

get_install_count(app_name:appname, exit_if_zero:TRUE);

install = get_single_install(app_name:appname, port:port);

dir = install['path'];
version = install['version'];

install_url = build_url(port:port, qs:dir);

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, appname, install_url);

if (version =~ '^10\\.' && ver_compare(ver:version, fix:"10.21.0001", strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 10.21.0001\n';
    security_note(port:port, extra:report);
  }
  else security_note(port:port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, version);
