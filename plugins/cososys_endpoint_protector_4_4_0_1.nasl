#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(72671);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/23 22:03:55 $");

  script_bugtraq_id(63996);
  script_osvdb_id(100483);

  script_name(english:"CoSoSys Endpoint Protector < 4.4.0.1 Unspecified XSS");
  script_summary(english:"Checks CoSoSys Endpoint Protector version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a data loss prevention web application that
is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of CoSoSys Endpoint Protector installed on the remote host
is prior to 4.4.0.1.  It is, therefore, affected by an unspecified
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"see_also", value:"http://www.endpointprotector.com/downloads/release_history");
  script_set_attribute(attribute:"solution", value:"Upgrade to CoSoSys Endpoint Protector 4.4.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cososys:endpoint_protector_appliace");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("cososys_endpoint_protector_detect.nasl");
  script_require_keys("www/cososys_endpoint_protector");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port    = get_http_port(default:443);

install = get_install_from_kb(appname:"cososys_endpoint_protector", port:port, exit_on_fail:TRUE);
version = install["ver"];
dir = install["dir"];
url = build_url(port:port, qs:dir + "/");

fixed_version = "4.4.0.1";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "CoSoSys Endpoint Protector", port, version);
