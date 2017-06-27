#TRUSTED 261b8b753f34c4113ae2fb50161e18f8a6692c32d672459d4f0ba70f832abf21b63e5fabe70c4635640cecec709095ddfa649c261bdf78bf4cd2b5dbe880e5ebbd2bd6404a3aaaf7af84f253f37aab83025a247de8da61380bb531f3cf0f4543df88c06629c2a9f822fe23f23bd2b468b31b15071a3b224bfdda14d437bbe6a2be520964635aa4c355c826dc71ef29cc30325cbae43c52274fdac76880a974f2e7db61f0205e1f71be8c930f44b516dc4c5193f5df946e1bf35c4bc3e0df00a6bf74774a568b3c44dc24e635b1ac2db828d031281f1e5b4695ab4384f06b06210d308559010e55f3bc94262a7faadd3eb6aec8cefa2feac271f73bebdc03c8af027915c101c1f2d18393f5ac4e8a44357cf5a6cf4e1b71213a991b56f22ac74ac489fd3215cbc11cf5d3d2a3c158dee0b2c1aae1b1a1d98034e2d99196dcb8332e34706db3794ae5938d7812bcf2f1d9bef90eebdd4769a4b12163e5a6ad39f1ff40321fe72b6b45c3bf028ba22a526aaed033f56ac4784e7d5cf38da784ee20eb793caf25ecfd02618417c8aa01d578f2c3e16691e96c9a40f4adf86bd995d7faa188d257b41abdcd48bd125a1c4902c2a253e9e214f5f7e6ac8d3abbb1ab6cf642db2a9696ce0332d67ff65fd38cf3334af3f74bbe2ae535b5350504c74373664e889f4a2a6b1ed3884ac80deb47dea5e391daa939bcabd4b96a1a58aa0ca6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78031);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-3357", "CVE-2014-3358");
  script_bugtraq_id(70132, 70139);
  script_osvdb_id(112040, 112041);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj58950");
  script_xref(name:"CISCO-BUG-ID", value:"CSCul90866");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140924-mdns");

  script_name(english:"Cisco IOS Software Multiple mDNS Gateway DoS Vulnerabilities (cisco-sa-20140924-mdns)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS
running on the remote host is affected by two unspecified denial of
service vulnerabilities in the multicast DNS (mDNS) implementation. A
remote attacker can exploit this issue by sending a specially crafted
mDNS packet to cause the device to reload.

Note that mDNS is enabled by default if the fix for bug CSCum51028 has
not been applied.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140924-mdns
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f9e02dba");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAMBAlert.x?alertId=35023");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35607");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35608");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuj58950");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCul90866");

  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140924-mdns.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/02");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

app = "Cisco IOS";
cbi = "CSCuj58950 and CSCul90866";
fixed_ver = NULL;

#15.0EZ
if (ver == "15.0(1)EZ" || ver == "15.0(1)EZ1")
  fixed_ver = "15.0(1)EZ2 or 15.0(2)EZ";
#15.1SY
else if (ver == "15.1(2)SY" || ver == "15.1(2)SY1")
  fixed_ver = "15.1(2)SY2";
#15.1XO
else if (ver == "15.1(1)XO")
  fixed_ver = "15.1(1)XO1";
#15.2E
else if (ver == "15.2(1)E")
  fixed_ver = "15.2(1)E2 or 15.2(2)E";
else if (ver == "15.2(1)E1")
{
  fixed_ver = "15.2(1)E2 or 15.2(2)E";
  cbi       = "CSCul90866";
}
#15.4S
else if (ver == "15.4(1)S")
  fixed_ver = "15.4(1)S0a, 15.4(1)S1, or 15.4(2)S";
#15.4T
else if (ver == "15.4(1)T" || ver == "15.4(1)T1")
  fixed_ver = "15.4(1)T2 or 15.4(2)T";

if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);

# mDNS check
override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_udp", "show udp");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^17\S+\s+\S+\s+5353\s+", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because mDNS is not enabled.");
}

if (report_verbosity > 0)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
