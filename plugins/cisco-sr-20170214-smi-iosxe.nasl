#TRUSTED 2f3c00a9d541010423a4806922ff070ce3a5268bd103a90ea9ccc2607ea93af3205a4b1e4c99432222c385ed07586f8ca1b0832eb56ef53010d4e6777aaa5807bac3a2f19c4af818c08cf6cb6812b076b58976313b7a1c6cce1b2efceea77a3ced0e3c9ec33273509cf49d800c90556939ed04e31ec0e217d04401a3582f48c5930860c4b93c20a339dc9d6e9d416a4a9998408534590360fc5e4a6bf26b083dc7715c9d9e206d1e3fc03e5b84c08871659729f4f2138540c40271ba091e8643456ca47fc4e4874e506d214b5e8cca8cdd9d531dea47713691a2fbc9bc4c2f33f954fe2ed1c8446258e9fcb36dc1e601c3bb86de8816a8ff7263ef0808ae913b628f35bfb3486606b0d844047f2eb6df270d986f085e36d18ae0889c98732ff7b5f09d854b2090c57f9f20a51e60954d62b6f7ca99b9efab235974981bbe1685a7edae029090215bf42643798c044daf0880e828b075b3a08deaa7bc43e58d20b0744a60df645417160e1947c23c05df88b4f2ad1786320ff8047f09e20a0d48a6c091231b9f3c9ca91803485a530194e30b92c6f2ae0ea66a0016e850dfd3fc717e7ef115a2f216710a60cbc8b4941258b07b48eae82602452b22de27a5127bb047b8de77a1e02f36bc82b93565eac9177e9be7dc16250002f814b9732c3f3ed8250978b4273258ee0fecbd2c877a8c976ed1666336b7a406fe219935d23738
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99234);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/06");

  script_name(english:"Cisco IOS XE Smart Install Protocol Misuse (cisco-sr-20170214-smi)");
  script_summary(english:"Checks the IOS XE configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The Smart Install feature is enabled on the remote Cisco IOS XE
device.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XE device has the Smart Install Feature enabled.
The Smart Install (SMI) protocol does not require authentication by
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

  - Load an attacker-supplied IOS XE image onto the IBC.
  
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

get_kb_item_or_exit("Host/local_checks_enabled");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

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
else audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS XE", ver);
