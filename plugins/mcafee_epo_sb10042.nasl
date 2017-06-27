#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66319);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_cve_id("CVE-2013-0140", "CVE-2013-0141");
  script_bugtraq_id(59500, 59505);
  script_osvdb_id(92800, 92801);
  script_xref(name:"CERT", value:"209131");
  script_xref(name:"EDB-ID", value:"33071");
  script_xref(name:"MCAFEE-SB", value:"SB10042");

  script_name(english:"McAfee ePolicy Orchestrator 4.6.x Multiple Vulnerabilities (SB10042)");
  script_summary(english:"ePO App Server version check");

  script_set_attribute(attribute:"synopsis", value:
"A security management application on the remote host has multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of McAfee ePolicy
Orchestrator running on the remote host has the following
vulnerabilities :

  - An unspecified SQL injection vulnerability exists in the
    Agent-Handler component.  A remote, unauthenticated
    attacker could exploit this to execute arbitrary code as
    root. (CVE-2013-0140)

  - An unspecified directory traversal vulnerability exists
    in the file upload process.  A remote, unauthenticated
    attacker could exploit this to upload arbitrary files.
    (CVE-2013-0141)");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10042");
  script_set_attribute(attribute:"solution", value:"Upgrade to ePolicy Orchestrator 4.6.6 / 5.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_epo_app_server_detect.nasl");
  script_require_keys("www/epo_app_server");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8443);
install = get_install_from_kb(appname:'epo_app_server', port:port, exit_on_fail:TRUE);
dir = install['dir'];
ver = install['ver'];
url = build_url(qs:dir, port:port);

# this should never be true but this code will be defensive anyway
if (ver == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_WEB_APP_VER, 'ePO Application Server', url);

if (ver =~ "^4\.6\.")
  fix = '4.6.6';
else if (ver =~ "^4\.5\.")
  exit(0, "This plugin does not currently test for the issue in ePO Application Server 4.5.");
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'ePO Application Server', url);

if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'ePO Application Server', url);

set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
