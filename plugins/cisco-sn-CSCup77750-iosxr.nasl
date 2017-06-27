#TRUSTED 5a4b677d513fceefc2e4c4be3deaac68eae428a01cda3c27e98a88e89e180b4d5a43b1b6de320976374fec36e5294d267f7ebacffaa496f290ca7fe13c9d8fb4a921c407fe4f7203bfe75bb43e080314c95b60b347e2468d56ecd15f9208d166ec8b8199ab2cd29f57eb9c5f16181e23486d16341af1babcf1a6aacfa127c52c89ac98d372f463c00b974bcca112fa7abec51eb467185d07eda4d17634ccfd1c3fafc528799da93cc7f2b92134a9ce5b62a6cbb782d73d4a94e2f1a09bbe5d7eff5b7077fc004834bd74ca9a6a0b9b9e77579d0c93a7040d224c5fa6672d5985e6e67eb5524fd6a76afa45c3e10aa78f88df38c6cbd903685c0bf58416a2c0c802f66e78fd0ac213b8ab300079ce14bd227c34a96b40871b8e3eaaea2eaa3674c7f7e492ae827c06dfba414dbdd84310ea918ebab5d78736cdb938542517ec12660e93a746251f1e15bbf403b2bc2863081e110b9cafa84cdc043a3b6d3085f42967986b45bae41b452b3a46695856522603b5acfeb1638e03234c00cf0425146be5bd4595e3084e66a074bccdc0136441c66c43621fdcc778fb3b855e5117c88c5fc718211095c5dc300a68cb09817b021e19aa8587ec0eae7a8f7a37ec5190c947313e182fda4b9d54e12ad78f75a14a9e0cc35098732dcfa03190c691b1d4ce55bcbe1190164ccd9b761c46235c106ff53169471ea24d33271a859a628c58
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77729);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-3335");
  script_bugtraq_id(69383);
  script_osvdb_id(110433);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup77750");

  script_name(english:"Cisco IOS XR NetFlow and Network Processor (NP) Chip DoS (Typhoon-based Line Cards)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version of Cisco IOS XR software
that is potentially affected by a denial of service vulnerability
related the handling of a maliciously crafted packet with a multicast
destination MAC address routed by a bridge-group virtual interface.

Note that this issue only affects Cisco ASR 9000 series devices using
Typhoon-based line cards with a Bridge Virtual Interface (BVI)
configured for egress NetFlow collection with a static ARP mapping a
unicast IP address to a multicast MAC address.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35416");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-3335
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e974efbe");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCup77750");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in Cisco bug ID CSCup77750.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version",  "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

# Check version
# 4.3.0/1/2 are affected
version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
if (version !~ "^4\.3\.[012]($|[^0-9])") audit(AUDIT_HOST_NOT, "affected");

# Check model
model = get_kb_item("CISCO/model");
if(!isnull(model) && model !~ "ciscoASR9[0-9]{3}") audit(AUDIT_HOST_NOT, "ASR 9000 series");
# First source failed, try another source
if (isnull(model))
{
  model = get_kb_item_or_exit("Host/Cisco/IOS-XR/Model");
  if ("ASR9K" >!< model) audit(AUDIT_HOST_NOT, "ASR 9000 series");
}

# Specific conditions are required
if (report_paranoia < 2) audit(AUDIT_PARANOID);

override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  # Check if CSCum91344 SMU is installed
  buf = cisco_command_kb_item("Host/Cisco/Config/show_install_active", "show install active");
  if (check_cisco_result(buf))
  {
    if (buf !~ "CSCum91344") audit(AUDIT_HOST_NOT, "affected because CSCum91344 SMU is not installed.");

    # Check if we have a Typhoon card, audit out if we don't
    buf = cisco_command_kb_item("Host/Cisco/Config/show_module", "show module");
    if (check_cisco_result(buf))
    {
      if (buf =~ "\sA9K-(MOD80|MOD160|24X10GE|36X10GE|2X100GE|1X100GE)-(SE|TR)\s") flag = TRUE;
      else audit(AUDIT_HOST_NOT, "affected because it does not contain a Typhoon-based card.");
    }
    else if (cisco_needs_enable(buf)) override = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected");
}

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : CSCup77750' +
    '\n  Installed release : ' + version + 
    '\n';
  security_warning(port:0, extra:report+cisco_caveat(override));
}
else security_warning(port:0, extra:cisco_caveat(override));
