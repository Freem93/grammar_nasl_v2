#TRUSTED aeedc8e3ceb2c3d7d10f03966b3c907bf649ccc5efc33dec3eed8d42bf30841038d9afc2b6f82e4bf4ffebf4902a92b2069381b064aad24c131c45bd78cda36e9ce207e9b2dabfa672e14753308610984fb126d9f98977d190d9b227b7dd07f56219a3924b7a0642aadaadde22d918fddde430e7997f329fec20fb11f960bfb156f75ca3ff40c1a08c75b9885fa0b5f5f99a5dd33f0fb3cd47d61254c9d7b6d3790639887a13dd798804d9eb14e7d33892c7a40caebd18d3253616260e8927fe27bf827a83ea7a02eb13acbc4ce50016d711e56334df01ad2880fb362683b094f052d682d96d01bc8b7142e1137d853c1bb5f103314106d777c503bb6752554a0ad13e0eba74c96611e201a562e42bed8dea106625f4556dc5da42006a5607a85c1eeff462792a6b83cfad4ec2778fd80e01d76e75ad2686d7032d0cc324826833b6a1b5c7e698d1dd545156121ace3efc57f9978dab50f3b84b03129ea416cc5b4ee01bebd7259fd736a909fa90036fa70762c6037346fd32159d062bcc84b35a51efa86fdabfd5314bcc0ae9e489afb2472b7280469e46b2f3232e8a3268fdf5b883d233654c1a86c7ad853d839bca7ca6d984bdc786430fbf8646b9f093006345db2f1f770e4376c5462d7c6adcefb3603ae87cca63ff40afe4d377f08833f6226ae87a929fe62f262cef31b89f34cca7e71e3e0d589f66a2a40584b11702
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93113);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/10/28");

  script_cve_id("CVE-2016-6366");
  script_bugtraq_id(92521);
  script_osvdb_id(143049);
  script_xref(name:"CISCO-BUG-ID", value:"CSCva92151");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160817-asa-snmp");
  script_xref(name:"EDB-ID", value:"40258");

  script_name(english:"Cisco ASA SNMP Packet Handling RCE (CSCva92151) (EXTRABACON)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its banner and configuration, the version of the remote
Cisco Adaptive Security Appliance (ASA) device is affected by a remote
code execution vulnerability, known as EXTRABACON, in the Simple
Network Management Protocol (SNMP) code due to a buffer overflow
condition. An authenticated, remote attacker can exploit this, via
specially crafted IPv4 SNMP packets, to cause a denial of service
condition or the execution of arbitrary code. Note that an attacker
must know the SNMP community string in order to exploit the
vulnerability.

EXTRABACON is one of multiple Equation Group vulnerabilities and
exploits disclosed on 2016/08/14 by a group known as the Shadow
Brokers.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160817-asa-snmp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?58b0c291");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCva92151");
  script_set_attribute(attribute:"see_also", value:"https://blogs.cisco.com/security/shadow-brokers");
  # https://www.riskbasedsecurity.com/2016/08/the-shadow-brokers-lifting-the-shadows-of-the-nsas-equation-group/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c7e0cf3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCva92151. Alternatively, as a workaround, change the SNMP community
string, and only allow trusted users to have SNMP access.

Additionally, administrators can monitor affected systems using the
'snmp-server' host command.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

# Convert 'Cisco versions' to dot notation
# a.b(c.d) to a.b.c.d
# a.b(c)d  to a.b.c.d
function toVerDot(ver)
{
  local_var ver_dot = str_replace(string:ver, find:'(', replace:'.');
  local_var matches = eregmatch(string:ver_dot, pattern:"^(.*)\)$");

  if (matches) ver_dot = matches[1];
  else ver_dot = str_replace(string:ver_dot, find:')', replace:'.');

  return ver_dot;
}

asa   = get_kb_item_or_exit('Host/Cisco/ASA');

app = "Cisco ASA";

ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

ver_dot = toVerDot(ver:ver);

fix = FALSE;

# versions 7.2, 8.0-8.7
if (ver =~ "^[78]\.[0-7]")
{
  # won't check granularity for this
  # affected; migrate to 9.1.7(9) or later
  fix = "9.1.7(9)";
}
# versions 9.0-9.6
else if (ver =~ "^9\.[0-6]")
{
  match = eregmatch(string:ver, pattern:"^9\.([0-9])");
  if (!isnull(match))
  {
    if (match[1] == "0")      fix = "9.0.4(40)";
    else if (match[1] == "1") fix = "9.1.7(9)";
    else if (match[1] == "2") fix = "9.2.4(14)";
    else if (match[1] == "3") fix = "9.3.3(10)";
    else if (match[1] == "4") fix = "9.4.3(8)";
    else if (match[1] == "5") fix = "9.5(3)";
    else if (match[1] == "6") fix = "9.6.1(11)";
  }
}

fix_dot = FALSE;
if (fix) fix_dot = toVerDot(ver:fix);

if ((!fix_dot) || ver_compare(ver:ver_dot, fix:fix_dot, strict:FALSE) >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, app, ver);

override = FALSE;
snmp_disabled = FALSE;
if (get_kb_item("Host/local_checks_enabled"))
{
  # Check if SNMP is enabled
  buf = cisco_command_kb_item(
    "Host/Cisco/Config/show_running-config",
    "show running-config snmp-server"
  );
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"no snmp-server enable", string:buf))
      snmp_disabled = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (snmp_disabled)
  audit(AUDIT_HOST_NOT, "affected because the SNMP server is not enabled");

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_hole(port:0, extra:report + cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
