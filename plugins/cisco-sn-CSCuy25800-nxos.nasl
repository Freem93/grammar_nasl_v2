#TRUSTED 65d06bb4900d1687ad60fb1f53fc204a56c9f99f9a9553221d83ff73d3dd1ee07dedc2b08cd470ec444cdd3ad027529dadd5d463bbea3ff12e05d38e9378284d3daba4d07c3201a2af48ce06e31a41772cc6030825d6715296c495adb6da66dbe1dcd409b28609fc533347937c5dc6da42860bba6be925ebc9a5e899396306e9d5f39ff917d57f28582b6bab631471f5b8383574dbe51139706fd4356f6ce39661fbf1c9a24667c472eb8cb720a8a7ddf24bb3296f18c18a8ec0bd36f50c6bd5840768f44af2535b1808ba50c9301cafcbece34de9806a07f948481f34a85fb570588478356dffe7f00c0f71d65962e6b6a8cc881f41dea5e83a0a28b8baf3434b377eebccdcd8d021fa5b6b113b2d794acaf4b7fd52a6e0a30bd406da1040ca070a9a257cfb7149b4cb9bb3791e83d2899dcefa0d98d3159523df8116947a4f0b331fd068e3a7a7ebd747d887e0476dcd91eca2fcbe9b624e9bd37d5a570fd314bc59de98584f27ea7f567260af293bd296737a5bd64b481a12bcccfa2b5c32fb23b1893146ebd75eea7f1809647d311ecc417e30447b6cffd9a20e4189df8ccd2e6f23d74d0e31779e65ca51b881c30ef039c687eb1b214247cc3c0bea9e9299dc3d52da3678d73e2a1428231317864639a0d743e9379bc12eac38e0888819cbe9a37980d3e45ecf80d0065f1aa142d9e674420afe4b807894f89f67b92eda
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89083);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/10/18");

  script_cve_id("CVE-2016-1329");
  script_osvdb_id(135228);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160302-n3k");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy25800");

  script_name(english:"Cisco Nexus 3000 and 3500 Insecure Default Telnet Credentials (cisco-sa-20160302-n3k)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Nexus device has a known set of hardcoded default
user credentials. An unauthenticated, remote attacker can exploit this
to authenticate remotely to the device via Telnet with the privileges
of the root user with bash shell access.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160302-n3k
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?52c3fe4b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuy25800. Alternatively, disable Telnet and use SSH for remote
connections to the device.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/03");

  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

device  = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model   = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");

# only affects nexus 3000 / 3500
if (device != 'Nexus' || model !~ '^3[05][0-9][0-9]([^0-9]|$)')
  audit(AUDIT_HOST_NOT, "Nexus Model 3000 or 3500");

version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

flag = 0;
override = 0;
fix = FALSE;
fix_map = make_array();

# 3000 versions
if (model =~ "^30[0-9][0-9]")
{
  fix_map = make_array(
    "6.0(2)U6(1)", "6.0(2)U6(1a)",
    "6.0(2)U6(2)", "6.0(2)U6(2a)",
    "6.0(2)U6(3)", "6.0(2)U6(3a)",
    "6.0(2)U6(4)", "6.0(2)U6(4a)",
    "6.0(2)U6(5)", "6.0(2)U6(5a)"
  );
}
else # 3500 versions
{
  fix_map = make_array(
    "6.0(2)A6(1)", "6.0(2)A6(1a)",
    "6.0(2)A6(2)", "6.0(2)A6(2a)",
    "6.0(2)A6(3)", "6.0(2)A6(3a)",
    "6.0(2)A6(4)", "6.0(2)A6(4a)",
    "6.0(2)A6(5)", "6.0(2)A6(5a)",
    "6.0(2)A7(1)", "6.0(2)A7(1a)"
  );
}

# Check for vulnerable version
foreach vuln_ver (keys(fix_map))
{
  if (version == vuln_ver)
  {
    flag += 1;
    fix = fix_map[vuln_ver];
    break;
  }
}

if (!flag)
  audit(AUDIT_HOST_NOT, "affected");

if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_feature", "show feature");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"(^|\r?\n)telnetServer[ \t]+\d+[ \t]+enabled($|\r?\n)", string:buf))
      flag++;
    # 3500 + 6.0(3)A6(1) credentials can also be used with SSH
    if (!flag && model =~ "^35" && version == "6.0(2)A6(1)")
    {
      if (preg(multiline:TRUE, pattern:"(^|\r?\n)sshServer[ \t]+\d+[ \t]+enabled($|\r?\n)", string:buf))
        flag++;
    }
  }
  else if (cisco_needs_enable(buf))
  { 
    flag++;
    override++;
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + device + ' ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
  }
  else security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
