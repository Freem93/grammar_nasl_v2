#TRUSTED 8e6204fea25fffd0d01b02e69a8d2cf53389385e2eb1a393a08a827e1ad99238ef6a29ad8c7e4fa926ec7689af1ce18162c672f81990a6a35088af0eda3709dbf8690c9f23ba7afdebffb08626d4c92f52ce6c14cebeff8a52908200d7fe1fecd9ae16203dc610addb7a2a5a8ecd114084fc1f5d19117d5fced56e1761802382ef00dbba4b79df0e00bc4e95ba03eeca005e02f44147618a728ac322195420dda84da05f3dad45f0a05a3855714d64d9440302e260e45260dfbe070980c7506c52304f00dced1013ccb05939f8a7ddfe22dcaa9954703df1675ce8adc8938d424c81b3e3942bff4602cafcbd4fa90340bfc7f8f725113f07073b49ed7d82417f460da77cd98c5553c7f6f58b5fe28483f36cc27113aed5468a7016330064d9beed92fb7842bde688bbd6764dc8945fa43aca57833e181576b278413594e46339bb0d06690d3a867df0674ba1cd3cc2dbfdf233e0ba0f70d1a34a3eebcd287c39bc8cfc701988b0c78f1f3ecb2bab1d17d3c69d884fcd762eaf6bb76faaf63507c93881c5906129fe21c0fe616dcbfd2eca47309e2e102b2a5134ca22b6aec1376808dd9a9742cabc9f58cc79c586ecb93ddf7bcbfb874885fbec9994f3f0d2accaa3cae21ca5422c4cbc864d236438befd3f2fb1196df3eeda482e6c1aec11f17d0a6069104708fc33c2fbcc6a30da321b91b28b5b55a57866d3a5f7052e54f0
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99233);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/06");

  script_name(english:"Cisco IOS Smart Install Protocol Misuse (cisco-sr-20170214-smi)");
  script_summary(english:"Checks the IOS configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The Smart Install feature is enabled on the remote Cisco IOS device.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS device has the Smart Install feature enabled. The
Smart Install (SMI) protocol does not require authentication by
design. The absence of an authorization or authentication mechanism in
the SMI protocol between the integrated branch clients (IBC) and the
director can allow a client to process crafted SMI protocol messages
as if these messages were from the Smart Install director. An
unauthenticated, remote attacker can exploit this to perform the
following actions :

  - Change the TFTP server address on the IBC.

  - Copy arbitrary files from the IBC to an
    attacker-controlled TFTP server.

  - Substitute the client's startup-config file with a file
    that the attacker prepared and force a reload of the IBC
    after a defined time interval.

  - Load an attacker-supplied IOS image onto the IBC.
  
  - Execute high-privilege configuration mode CLI commands
    on an IBC, including do-exec CLI commands.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityResponse/cisco-sr-20170214-smi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee7d2a89");
  script_set_attribute(attribute:"solution", value:
"Disable the Smart Install feature.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

get_kb_item_or_exit("Host/local_checks_enabled");

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

flag = 0;
override = 0;

cmds = make_list();

buf = cisco_command_kb_item("Host/Cisco/Config/show_vstack_config", "show vstack config");
if (check_cisco_result(buf))
{
  if ( (preg(multiline:TRUE, pattern:"Role:\s*[Cc]lient", string:buf)) &&
       (!preg(multiline:TRUE, pattern:"Role:\s*[Cc]lient\s+\(SmartInstall disabled\)", string:buf)) )
  {
    cmds = make_list(cmds, "show vstack config");
    flag = 1;
  }
}
else if (cisco_needs_enable(buf))
{
  flag = 1;
  override = 1;
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_NOTE,
    override : override,
    version  : ver,
    cmds     : cmds
  );
  exit(0);
}
else audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS", ver);
