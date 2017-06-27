#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97213);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/21 15:06:14 $");

  script_cve_id("CVE-2017-3896");
  script_bugtraq_id(95903);
  script_osvdb_id(151236);
  script_xref(name:"MCAFEE-SB", value:"SB10183");
  script_xref(name:"IAVA", value:"2017-A-0035");

  script_name(english:"McAfee ePolicy Orchestrator Agent < 5.0.4.449 Log Viewer DoS");
  script_summary(english:"McAfee Agent version check.");

  script_set_attribute(attribute:"synopsis", value:
"A security management application agent running on the remote host is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the McAfee ePolicy
Orchestrator (ePO) Agent running on the remote host is 5.0.x prior to
5.0.4.449. It is, therefore, affected by a flaw in its remote log
viewer component due to improper validation of input to an unspecified
HTTP GET parameter. An unauthenticated, remote attacker can exploit
this, via a specially crafted URL request, to cause a denial of
service condition.

Note that that exploitation of this vulnerability requires that both
the Agent's log viewing functionality is enabled and the remote log
access is not restricted to ePO administrators only. However, these
are not set by default.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10183");
  script_set_attribute(attribute:"solution", value:
"Upgrade McAfee ePO Agent to version 5.0.4.449 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator_agent");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("mcafee_epo_agent_remote_log_detect.nasl");
  script_require_keys("installed_sw/McAfee ePO Agent");
  script_require_ports("Services/www", 8081);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "McAfee ePO Agent";
port = get_http_port(default:8081, embedded:TRUE);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);
ver = install['version'];

# Only 5.0.x is affected
if (ver !~ "^5\.0\.") audit(AUDIT_INST_VER_NOT_VULN, app, ver);

fix = '5.0.4.449';
if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, app, ver);

report =
  '\n  Installed version : ' + ver +
  '\n  Fixed version     : ' + fix + '\n';

security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
