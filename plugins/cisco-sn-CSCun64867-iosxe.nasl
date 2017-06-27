#TRUSTED a2a9dceda2107f8b24866d2c16bc086b178d97feb80e3cb3e6ad451c37a1214d4f3c5f440965ed2167fc61dc86eed1b49d00ef494cf0776b49f330e411ac7d4aa0907538c32fe24586ee310348d1c05c8401b73d72d2095b589c6330d10bfc5a6d1b9c6662bb960f71c9af437b4629121291942411d1a267391d6e08a2393aef776de3313039333e6bb3e4337d04c60dc5f2e102a3f6e5230ffeaf7c07c7b4e2c93e275b4706839e31c664d245332799a633d1ae74ff6954db4c438ef59bb5239a927d581a3923427fb01a43b3e214eae1c7cedd11247b0a769698f9689320051f671712c843788814f52f9f2112ea1f41faa7ddf4471dab3e4a0fd04799dcbdcbb48fe1e912061a6f51e53fd19c2db1d6989a07f379e25f8dc8614d66e83c4737ccc388862a27427bda31bf27ccd1fdb2622da35c887adf6d05caef00b717f1c9ae5f92977368ab27289fc4696d714c3189b1588e790d7f87138641207d0d77cae8468b701a2231b69de477db02a16f6b6edb81697ff790d24226cb88ffe00985045e0867693526f503039f6d7238217c60d8c6f05d1a2e26e1e62beacba12d3a339cff6d215daa7cfb8b04af64108299a73220cf1b1e18f457704704eaac921bcb160d2b23e38c6112497558ba95c1545c9618ba7a502e8159bc09002fc3c586774a592a0e8cbfe221b551e436ac47799970773b04cadd83e3127fdc1abc32
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76972);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-3290");
  script_bugtraq_id(68021);
  script_osvdb_id(108065);
  script_xref(name:"CISCO-BUG-ID", value:"CSCun64867");

  script_name(english:"Cisco IOS XE mDNS Manipulation (CSCun64867)");
  script_summary(english:"Checks IOS XE version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by a manipulation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote IOS XE device is
affected by a manipulation vulnerability.

A flaw exists due to unconstrained autonomic networking with mDNS
(multicast Domain Name System). This could allow a remote attacker to
read or overwrite autonomic networking services.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=34613");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-3290
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80adf2de");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCun64867.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag = 0;
override = 0;

if (version == '3.12.0S') flag++;
if (version == '3.13.0S') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag > 0)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if ("mdns" >< buf) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag > 0)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCun64867' +
    '\n  Installed release : ' + version;
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
