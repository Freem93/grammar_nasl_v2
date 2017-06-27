#TRUSTED 7ddcc40c083b65d78dc99eee30cf3b3f7e1b671bd3a5b4293fd0fec4b62ea3b69b5b5576ca63c45d74afb4caf074c7022da4c18191b50f1c0fd2668f64c73217149fedcaf0765f7cf053670e3d0878cd0e7fc7377935228ae75a190b16c3a0794844e59c434b7e2ed2ab0aeba39b6cd576e14b45cfa46094e16241bbbb18b3337031b20d61de1ecddbc4302eefcc5441ad6a16dbec3510c67f786af2a28a8565cfc9a7b409771d725bd60f851ff82a986f116d90c5c5976bdce93c15fbdd6ce8bc6fccb7d424637945ad35ddc051666af677a616cfca4ebc6a8bcdbd7918d41295cc8afc9c00897da87e28413f9163b1a3acc6ffdbfe56d02f5748aac10fa73a85b37c5d824deae37e257597f6f010644cf8dbca8b4bb0d5e3f0f5b356e9f50f35e599f9cfbe443ff069fee1dad54c124b37dffb947f96ef218e1250063b5ea68db863b1929c0a8e2ee896e8bbed91fd3e01b35f5f10b1ca2fa0a7d941dbc35e97935133e8dd12d7c87ff529e78757b9619591feefa69e996fcffdf183c62c74460d62bb5cdb2075ba6ddf6e7dd6878cc3f8eed82688e05dd7103a2613c768cecc3e610941c3e0dd2a32b4f9b9853cd8f343064c0e9e952af4c62f1bbba9178fa9b7b1d487a49e54cc819ac2e1075c632f05216b007cc40dfc5b91108266fb6056fab871fbc895bdf799c11949283caa6bf6ae14784c80a976d09a739ca61055
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20110928-smart-install.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(56320);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/03");

  script_cve_id("CVE-2011-3271");
  script_bugtraq_id(49828);
  script_osvdb_id(75916);
  script_xref(name:"CISCO-BUG-ID", value:"CSCto10165");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20110928-smart-install");

  script_name(english:"Cisco IOS Software Smart Install Remote Code Execution Vulnerability (cisco-sa-20110928-smart-install)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability exists in the Smart Install feature of Cisco Catalyst
Switches running Cisco IOS Software that could allow an
unauthenticated, remote attacker to perform remote code execution on
the affected device. Cisco has released free software updates that
address this vulnerability. There are no workarounds available to
mitigate this vulnerability other than disabling the Smart Install
feature."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20110928-smart-install
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6a0f8bbc"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20110928-smart-install."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/29");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}



include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
if ( version == '12.2(52)EX' ) flag++;
if ( version == '12.2(52)EX1' ) flag++;
if ( version == '12.2(52)SE' ) flag++;
if ( version == '12.2(53)EY' ) flag++;
if ( version == '12.2(53)SE' ) flag++;
if ( version == '12.2(53)SE1' ) flag++;
if ( version == '12.2(53)SE2' ) flag++;
if ( version == '12.2(55)EX' ) flag++;
if ( version == '12.2(55)EX1' ) flag++;
if ( version == '12.2(55)EX2' ) flag++;
if ( version == '12.2(55)EY' ) flag++;
if ( version == '12.2(55)EZ' ) flag++;
if ( version == '12.2(55)SE' ) flag++;
if ( version == '12.2(55)SE1' ) flag++;
if ( version == '12.2(55)SE2' ) flag++;
if ( version == '15.1(3)T' ) flag++;
if ( version == '15.1(3)T1' ) flag++;
if ( version == '15.1(4)M' ) flag++;
if ( version == '15.1(4)M0a' ) flag++;
if ( version == '15.1(4)M0b' ) flag++;
if ( version == '15.1(4)M1' ) flag++;
if ( version == '15.1(4)XB4' ) flag++;
if ( version == '15.1(4)XB5' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_vstack_config", "show vstack config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"Role:\s+\(Client\|Director\)", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}



if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
