#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88595);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/28 18:15:08 $");

  script_cve_id("CVE-2016-1305");
  script_bugtraq_id(82318);
  script_osvdb_id(133859);
  script_xref(name:"CISCO-BUG-ID", value:"CSCux15511");
  script_xref(name:"IAVB", value:"2016-B-0022");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160201-apic-em");

  script_name(english:"Cisco APIC-EM 1.1 Unspecified XSS (credentialed check)");
  script_summary(english:"Checks the APIC-EM version number.");

  script_set_attribute(attribute:"synopsis", value:
"A network management system running on the remote host is affected by
an unspecified reflected cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Cisco Application
Policy Infrastructure Controller Enterprise Module (APIC-EM)
application running on the remote host is version 1.1. It is,
therefore, affected by a reflected cross-site scripting vulnerability
due to improper sanitization of input before returning it to users. A
remote attacker can exploit this, via a specially crafted request, to
execute arbitrary script code in a user's browser session.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160201-apic-em
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6beb8017");
  script_set_attribute(attribute:"solution", value:"Contact the vendor for a fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:application_policy_infrastructure_controller_enterprise_module");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_apic_webui_detect.nbin");
  script_require_keys("installed_sw/Cisco APIC-EM", "Settings/ParanoidReport");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Cisco APIC-EM";

get_install_count(app_name:app, exit_if_zero:TRUE);

# Cisco is really vague about what is vulnerable, so we will be flagging 1.1.x
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

fix = "See Vendor.";
port = get_http_port(default:443);
install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

url = build_url(qs:install['path'], port:port);
ver = install['version'];

report = NULL;
if (ver =~ "^1\.1\.")
{
  set_kb_item(name: 'www/' + port + '/XSS', value: TRUE);
  if (report_verbosity > 0)
  {
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix;
  }

  security_warning(port:port, extra:report);
  exit(0);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, ver);
