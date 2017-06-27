#TRUSTED 70295e1f117b64582563eff2c3f9e3d729dac0e135ec0aa1423bc2518fe893d3b5af1d0af83dba4298b9ce68edbe8da4c88f3a5d2dfd8e29c3d7b0999598fd78dc6bbfffada9f9c325db836571d2488c699ae9525fe8c15f06d3377665a6f3828a6d1ea1efaa37df6ace439930d6fa7e1d52059f36fc1791f98fb78177133efa1e77d63cbf3585253502198a6f46784bda4d2e2943fdf6dc8c5c6a57393a3f0c4f1dc5878ee93657f931be4873b6f2be98fa56709f50914021a5a90f475361d0f65ad86e7a60e514a1dda78757939de380ad301c88a46937c9048888d745726e8952e7c39759d79e4bb59b34e0ca2caa70adbde0f092a82da0ca1ec2b00c5e799acd767bca8c9ca017178740d087cff44db27b95e6fd5a91ea1235772d773c4523a9a0483c50be79bb470f7528a6aa2ac57dbb9cdc94caf71837d9a33d448bf9f72079943db01d48545d70ae5c54ac4c8acec225c8e88629c384541b5b469c429d6c8d5d05042c23f0a643247c88d1110ce325d7bafea7c1f4aeff1b5fa2c876f9a1c2ecd2edacb65e560832fe9ded1c2f3b7595dddede52ce704bf3bfbaffdaa73eb19bfc7597cdaa867e91b38b4ce082d26fcffb93deaf597e7e68e6af812266bac0b72ad3c2e87d30a49d0873369b0e73953905b6ca0d7f5f439f46e03e855e765229cb23d4473e47719ad2fd47b4e1d92293bee3d569aa9d6f62110f493b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93562);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/09/16");

  script_cve_id("CVE-2016-1347");
  script_bugtraq_id(85306);
  script_osvdb_id(136245);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq59708");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-l4f");

  script_name(english:"Cisco IOS Software Wide Area Application Services Express DoS");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco IOS running on the remote device is affected by a
denial of service vulnerability in the Wide Area Application Services
(WAAS) Express feature due to improper validation of TCP segments. An
unauthenticated, remote attacker can exploit this, via a crafted TCP
segment, to cause the device to reload, resulting in a denial of
service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-l4f
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba0706f1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuq59708");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug ID CSCuq59708.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");
  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

vuln     = FALSE;
override = FALSE;

vuln_versions = make_list(
  "15.5(2)T3",
  "15.4(2)T4",
  "15.4(2)T3",
  "15.4(2)T2",
  "15.4(2)T1",
  "15.4(1)T2",
  "15.4(1)T1",
  "15.4(1)T",
  "15.3(1)T2",
  "15.2(2)T"
);

foreach ver (vuln_versions)
{
  if (ver == version)
  {
    vuln = TRUE;
    break;
  }
}

if (!vuln) audit(AUDIT_INST_VER_NOT_VULN, 'Cisco IOS', version);

bug = '';

# Check for WAAS Express
if (vuln && get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config",
                              "show running-config");
  if (check_cisco_result(buf))
  {
    # WAAS Express
    if (preg(multiline:TRUE, pattern:"^\s*waas enable", string:buf))
      bugs = make_list("CSCuq59708");
  }
  else if (cisco_needs_enable(buf))
  {
    bug      = "CSCuq59708";
    override = TRUE;
  }
}

if (empty_or_null(bug)) audit(AUDIT_HOST_NOT, "affected");

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug IDs     : ' + bug +
    '\n  Installed release : ' + ver +
    '\n';
  security_hole(port:0, extra:report + cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
