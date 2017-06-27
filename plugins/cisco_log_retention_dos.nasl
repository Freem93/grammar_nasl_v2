#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62182);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/06/10 20:42:51 $");

  script_cve_id("CVE-2012-4629");
  script_bugtraq_id(55515);
  script_osvdb_id(85500);
  script_xref(name:"CISCO-BUG-ID", value:"CSCub70603");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120912-asacx");

  script_name(english:"Cisco Prime Security Manager Log Retention DoS (cisco-sa-20120912-asacx)");
  script_summary(english:"Checks the PRSM version.");

  script_set_attribute(attribute:"synopsis", value:
"The management application running on the remote host is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Cisco
Prime Security Manager running on the remote is affected by a denial
of service vulnerability. Making unspecified requests can cause log
files to exhaust the /var/log partition. A remote, unauthenticated
attacker can exploit this to make the system unresponsive.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120912-asacx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e9b2510f");
  # http://www.cisco.com/cisco/pub/software/portal/select.html?&mdfid=284397197&flowid=33362&softwareid=284399945
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac18b3cf");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cisco Prime Security Manager 9.0.2-103 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_security_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_prsm_web_detect.nasl");
  script_require_keys("installed_sw/Cisco PRSM");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("http_func.inc");
include("install_func.inc");
include("cisco_func.inc");

app = "Cisco PRSM";

port = get_http_port(default:443);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);
base_url = build_url(qs:install['path'], port:port);
ver = install['version'];

fix = '9.0.2 (103)';

if (cisco_gen_ver_compare(a:ver, b:fix) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + base_url +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, base_url, ver);
