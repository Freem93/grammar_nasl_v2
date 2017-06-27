#TRUSTED 186bab5e6b557a25fe9b3665b50ef5cad3de3058b28e740b704e568c7127dd4fc32662fbd6bb442335805a025edc446390327bbcacac000b4a05116ba9fa36f36134b66a935845a1b2cc6b053ca2084d08cf46a8d11f49ba21d0e0ca8af83f3f7bb1fc864f171eea59b9ab9c6974bec56afcb598b59bad8b467b92f1d8eede607b1ca12ed848e52f7a36c0beeb0357f324488f54170b32f96cc1035a85e5ff46aeab36a6fc4fc6a0f516896d716f53681fa87397c55c03952a968745a05ed7372a785908e6fd84f3657449d5480d3dbbb43c1d412f520574fe877a80b4f637decb810ac5889608ee3c477289f1109a684dde6500882539f16a5e7b2ca00679861face8071c64011b1ee9f856c3d953d4217d7b6a284c8a81ca95f96ee10c42930f9f4d752079ffba6f3b438629334feab9a810a4c667b4f48bcd560718904160bffec5b166dbf7f0c77a8f082a26e393e7e5863986ca6b0cf32aab40540ac64cc28e508b7ed26dfe320d37f050642626433c9d53031c392c33b78864224b02963f6fbfbb16d7da4c6887a7793c016c6d7f2c986115acd80a089f4430c307067fa3074bdfd6b0351bcc209957fc6beef712ee9db2829a91a1b38b1f6b833c9a8acf46aec9f6119ae7f3729071abd13b1c42b746670d1d65f7e6d4af4ff73fb7daa9e5bc69b499beea152ff1bac068993bd42dd204888726a58a426e0b47dcfca5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77222);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-3321");
  script_bugtraq_id(68536);
  script_osvdb_id(109165);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo91149");

  script_name(english:"Cisco IOS XR MPLS and Network Processor (NP) Chip DoS (Typhoon-based Line Cards)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version Cisco IOS XR software
that is potentially affected by a denial of service vulnerability
related the handling of maliciously crafted MPLS (Multiprotocol Label
Switching) packets routed by a bridge-group virtual interface.

Note that this issue only affects Cisco ASR 9000 series devices using
Typhoon-based line cards and MPLS.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=34936");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-3321
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?03811827");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuo91149");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in Cisco bug ID CSCuo91149.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
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

# This requires a very specific and non-supported
# configuration to make the device vulnerable
# which is why this is a paranoid check
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Check version
# Affected list from vendor:
# 4.3.0/1/2 and 4.3.4.MPLS
version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
if (version !~ "^4\.3\.[0124]($|[^0-9])")
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS XR", version);

# Check model
model = get_kb_item("CISCO/model");
if(model && model !~ "ciscoASR9[0-9]{3}") audit(AUDIT_HOST_NOT, "ASR 9000 series");
# First source failed, try another source
if(!model)
{
  model = get_kb_item_or_exit("Host/Cisco/IOS-XR/Model");
  if ("ASR9K" >!< model) audit(AUDIT_HOST_NOT, "ASR 9000 series");
}

# Example output from 'show mpls interfaces'
#Interface              IP         Tunnel   Operational
#Ethernet1/1/1          Yes (tdp)  No       No
#Ethernet1/1/2          Yes (tdp)  Yes      No
#Ethernet1/1/3          Yes (tdp)  Yes      Yes
#POS2/0/0               Yes (tdp)  No       No
#ATM0/0.1               Yes (tdp)  No       No          (ATM labels)
#ATM3/0.1               Yes (ldp)  No       Yes         (ATM labels)
#ATM0/0.2               Yes (tdp)  No       Yes

override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_mpls_interfaces", "show mpls interfaces");
  if (check_cisco_result(buf))
  {
    # Check if we have an operational MPLS interface, audit out if we don't
    if(
      buf !~ "^Interface\s+IP\s+Tunnel\s+Operational" || # Does buf have the right header
      buf !~ "\s+Yes\s+(\(ATM labels\))?(\n|$)"          # Does buf have a line that ends in Yes or Yes (ATM labels)
    ) audit(AUDIT_HOST_NOT, "affected because no MPLS interfaces are operational.");

    # Check if we have a Typhoon card, audit out if we dont
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
    '\n  Cisco bug ID      : CSCuo91149' +
    '\n  Installed release : ' + version + 
    '\n';
  security_warning(port:0, extra:report+cisco_caveat(override));
}
else security_warning(port:0, extra:cisco_caveat(override));
