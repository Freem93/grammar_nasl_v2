#TRUSTED 29a5c36266c88cf61a62aa3466b4bfcae72a71c5a4bd52adc0b982f4b02d73977898501f248c03c19c9bd0486591cf1b6a8125e52c96ab6c2d95008f8b4e1b19f7708706295f42b2f8c49bb82e102ec97bc00a482831b04a40a40c0eca3155c3df1f5442202f62f94325d0cc2b6903ff6d56e6832036509b7ec9576cc63849847eaee966b25f89b6d7c7a6257870f3eede14c8a4676b5c97310d92949ece30bdc14f5d37c90d8e7f321fede9c3d28cadfbcc2f859a05fccd7a463abe7c66c4a84dbd523a21aed05db512daa1bbc3a03b433aaee12b3cf96768efcffe2b619f9bffc3bd5557979791f577c7383c0269ec46a985f04f519e047795d53ec23b1c1f34b403fe62a26299092a0313783c6b4c665a39f380a241d6ecafd72ebdfd7031bcb05561bd8eb7c2a1cff7068a6cb6e7f362cf4e9747101c7c8be843b7212ea110fdaa60abecb512e5dbe7e398a2ceb538e00c803fd2008cf38b2df49681f3e7238b21aa89a871055650c73af9ca0b3a3856e52806c1e0e37678f178efe7f7be3a134ffb19e514fd7677dfd5e2c18e8d04575a63239594ca1fe3cd2efc6ab30fed15dffbf3759ce2956916506f4cd56b3fa319716ef73de4b2029a282b75eb95417608b072bbd74b7a2cbc2dbe374565aaebf0b2abf12964280c22046193f1101cec46ae68cdec0988ba0eeb3bf6974e3fc576d6460dc56dac4131f954565117
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77051);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-3308");
  script_bugtraq_id(68351);
  script_osvdb_id(108710);
  script_xref(name:"CISCO-BUG-ID", value:"CSCun83985");

  script_name(english:"Cisco IOS XR Software Static Punt Policer DoS (CSCun83985)");
  script_summary(english:"Checks the IOS XR version.");
  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XR
running on the remote host is affected by a denial of service
vulnerability due to a missing static punt policer. A remote,
unauthenticated attacker can cause the device to lock up by rapidly
sending specially crafted packets.

Note that this issue only affects Trident-based line cards on Cisco
ASR 9000 series routers.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-3308
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?28de3046");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=34843");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in Cisco Bug ID CSCun83985.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

# check model
model = get_kb_item("CISCO/model");
if (!isnull(model) && model !~ "ciscoASR9[0-9]{3}")
  audit(AUDIT_HOST_NOT, "affected");
if (isnull(model))
{
  model = get_kb_item_or_exit("Host/Cisco/IOS-XR/Model");
  if ("ASR9K" >!< model) audit(AUDIT_HOST_NOT, "affected");
}


version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");

# A patch is available for version 5.1.2
if (report_paranoia < 2 && version == "5.1.2") audit(AUDIT_PARANOID);

if ( version !~ "^5\.1\.[0-2]$" )
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco IOS XR', version);

override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_diag", "show diag");
  if (check_cisco_result(buf))
  {
    pat = "A9K-(40GE-L|40GE-B|40GE-E|4T-L|4T-B|4T-E|8T/4-L|8T/4-B|8T/4-E|2T20GE-L|2T20GE-B|2T20GE-E|8T-L|8T-B|8T-E|16T/8-B)";
    if (preg(multiline:TRUE, pattern:pat, string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because the device does not use any Trident-based line cards.");
}

if (report_verbosity > 0)
{
  report =
    '\n  Cisco Bug ID      : CSCun83985' +
    '\n  Installed release : ' + version + 
    '\n';
  security_warning(port:0, extra:report+cisco_caveat(override));
}
else security_warning(port:0, extra:cisco_caveat(override));
