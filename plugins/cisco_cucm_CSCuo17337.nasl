#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76121);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/04/27 19:46:26 $");

  script_cve_id("CVE-2014-3287");
  script_bugtraq_id(68000);
  script_osvdb_id(107849);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo17337");

  script_name(english:"Cisco Unified Communications Manager Java Interface SQL Injection (CSCuo17337)");
  script_summary(english:"Checks the version of Cisco Unified Communications Manager.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Cisco Unified
Communications Manager (CUCM) device is affected by a SQL injection
vulnerability in 'BulkViewFileContentsAction.java'. An authenticated,
remote attacker can exploit this, by using a crafted 'filename'
parameter, to execute arbitrary SQL commands to access sensitive
information.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=34572");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuo17337.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver         = get_kb_item_or_exit("Host/Cisco/CUCM/Version");
ver_display = get_kb_item_or_exit("Host/Cisco/CUCM/Version_Display");

app_name  = "Cisco Unified Communications Manager (CUCM)";

fixed_ver = FALSE;

if (ver =~ "^10\.0\." && ver_compare(ver:ver, fix:"10.0.1.12007.1", strict:FALSE) < 0)
  fixed_ver = "10.0.1.12007-1";

if(!fixed_ver) audit(AUDIT_INST_VER_NOT_VULN, app_name, ver_display);

set_kb_item(name:'www/0/SQLInjection', value:TRUE);

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : CSCuo17337'     +
    '\n  Installed release : ' + ver_display +
    '\n  Fixed release     : ' + fixed_ver   +
    '\n';

  security_warning(port:0, extra:report);
}
else security_warning(0);
