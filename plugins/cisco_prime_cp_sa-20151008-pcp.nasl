#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91344);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/31 17:32:09 $");


  script_cve_id("CVE-2015-6329");
  script_bugtraq_id(77050);
  script_osvdb_id(128674);
  script_xref(name:"CISCO-BUG-ID", value:"CSCut64074");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151008-pcp");

  script_name(english:"Cisco Prime Collaboration Provisioning 10.6.x / 11.0.x < 11.0.0.815 Web Framework SQLi (cisco-sa-20151008-pcp)");
  script_summary(english:"Checks the Cisco Prime Collaboration Provisioning version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote network management device is affected by a SQL injection
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Cisco Prime
Collaboration Provisioning (PCP) device is 10.6.x or 11.0.x prior to
11.0.0.582. It is, therefore, affected by a SQL injection
vulnerability in the web framework component due to improper
sanitization of user-supplied input before using it in SQL queries. An
authenticated, remote attacker can exploit this to inject or
manipulate SQL queries in the back-end database, allowing for the
manipulation or disclosure of arbitrary data.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151008-pcp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ffcc0c2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Prime Collaboration Provisioning version 11.0.0.815
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_collaboration_provisioning");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_prime_collaboration_provisioning_detect.nbin");
  script_require_keys("Host/Cisco/PrimeCollaborationProvisioning/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "Prime Collaboration Provisioning";
version = get_kb_item_or_exit("Host/Cisco/PrimeCollaborationProvisioning/version");

if (version == "10" || version == "11" || version == "11.0" || version == "11.0.0")
  audit(AUDIT_VER_NOT_GRANULAR, appname, version);

fix = '11.0.0.582'; # This was the first internal release with fix
report_fix = '11.0.0.815'; # First public release with fix

if(
  version =~ "^(10\.6|11\.0)([^0-9]|$)" &&
  ver_compare(ver:version, fix:fix, strict:FALSE) == -1
)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + report_fix +
    '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_WARNING, sqli:TRUE);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, version);
