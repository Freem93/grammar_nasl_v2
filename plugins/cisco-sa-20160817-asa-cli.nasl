#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93347);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/03/06 20:57:54 $");

  script_cve_id("CVE-2016-6367");
  script_bugtraq_id(92520);
  script_osvdb_id(143064);
  script_xref(name:"EDB-ID", value:"40271");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtu74257");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160817-asa-cli");

  script_name(english:"Cisco ASA Software CLI Invalid Command Invocation (cisco-sa-20160817-asa-cli) (EPICBANANA)");
  script_summary(english:"Checks the ASA version and for PIX and FWSM.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The Cisco Adaptive Security Appliance (ASA) is missing a
vendor-supplied security patch. It is, therefore, affected by a flaw
in the command-line interface (CLI) parser related to processing
invalid commands. An authenticated, local attacker can exploit this,
via certain invalid commands, to cause a denial of service condition
or the execution of arbitrary code.

Note that this vulnerability also affects Cisco PIX Firewalls and the
Cisco Firewall Services Module (FWSM).

EPICBANANA is one of multiple Equation Group vulnerabilities and
exploits disclosed on 2016/08/14 by a group known as the Shadow
Brokers.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160817-asa-cli
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d41baf38");
  # https://www.riskbasedsecurity.com/2016/08/the-shadow-brokers-lifting-the-shadows-of-the-nsas-equation-group/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c7e0cf3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security
Advisory cisco-sa-20160817-asa-cli.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firewall_services_module_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:pix_firewall_software");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_ports("Host/Cisco/ASA", "Host/Cisco/ASA/model", "Host/OS", "Host/Cisco/FWSM/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

cbi = "CSCtu74257";

# FWSM is considered EOL and all versions are affected
if (ver = get_kb_item('Host/Cisco/FWSM/Version'))
{
  report =
    '\n  Cisco bug IDs     : ' + cbi +
    '\n  Installed release : FWSM ' + ver +
    '\n  Fixed release     : N/A' +
    '\nCisco FWSM devices have reached end of life and no fix will be' +
    '\nprovided.';

  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
  exit(0);
}

# PIX is considered EOL and all versions are affected
if (get_kb_item("Host/OS") && ver = eregmatch(string:get_kb_item("Host/OS"), pattern:"CISCO PIX\s+([0-9a-zA-Z\.\(\)]+)[^\s\r\n]*"))
{
  report =
    '\n  Cisco bug IDs     : ' + cbi +
    '\n  Installed release : PIX ' + ver[1] +
    '\n  Fixed release     : N/A' +
    '\nCisco PIX devices have reached end of life and no fix will be' +
    '\nprovided.';

  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
  exit(0);
}

# Check ASA models and versions
asa = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');
ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

if (
  model !~ '^55[0-9][0-9]($|[^0-9])'
) audit(AUDIT_HOST_NOT, "ASA 5500 5500-X");

flag = 0;
override = 0;
local_check = 0;
fixed_ver = "";
report = "";


# For each vulnerability, check for affected OS versions,
# set "fixed" os version, and perform any additional checks

if (ver =~ "^7\.2[^0-9]" || ( ver =~ "^8\.[0-4][^0-9]" && check_asa_release(version:ver, patched:"8.4(3)")))
{
  flag++;
  fixed_ver = "8.4(3)";
}
else if (ver =~ "^8\.[5-7][^0-9]" || ( ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(1)")))
{
  flag++;
  fixed_ver = "9.0(1)";
}

if (flag)
{
  security_report_cisco(
    port:     0,
    severity: SECURITY_HOLE,
    bug_id:   cbi,
    version:  ver,
    fix:      fixed_ver
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
