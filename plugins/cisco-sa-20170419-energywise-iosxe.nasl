#TRUSTED 76ad95cf03153c4dc002db35d7d2968e7a6c41dc7f226db3d914271447fc27cfa7f30a914f74ec98284ee5884644d9035cb65cae0585754e8533bf874e8ede5aa525ca8abfbc84b5e96fdbd17890ecb71641c0f3ec83479646eccb3c0697213f1470d7410b7ce15673084c342097c9b24d9ca5247903ef4c8ec928e923fc35af120979366899a55e22bc89f68c1d592a23898a4ed19baab17371cd4d245eb597fd8f5e10c8e21f512eb89bed26779eee422a952541fecdacff09645aaa4899fc23c8cb39e10f1e4029658103c6fbd75df888a619ac41612c47ba11c195b14e4551485ee77db02ac54567f0b79abd58cc26db9e72423d37b7c7867396bf0b9840422a41f4208c137876fe787e9b567b2012d6fa79d72d0b3aa21087c376900ca2b37c668df07ffdaee9fbcd3e88cc10ce081cc3a60127302c99a009f63aae90c36b114bdfd0211596043d890e254ed1ee5c9d56bed24681eef4cebb858acb65da56493cefc0b66fc6103261c13c4ae00c43f197fafc3ade7f4b7de798dab0cb0b58c809794d4ef869ca3e3459453d1b7d5e6d57c967b61d0f3408e9aa07ce040e59db5a5a90561f07dae677650f869dd99dbba467b82aa860463679a1e72f4af55f545f9d45190dbf24f15f81e8d7e0d8b845e282417d4367bc0c08207374f768b681c9e951d8fbff11cb1a728a9e5d0ff9f7634c2044f94ee28653c62041bbeb
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99688);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/26");

  script_cve_id(
    "CVE-2017-3860",
    "CVE-2017-3861",
    "CVE-2017-3862",
    "CVE-2017-3863"
  );
  script_bugtraq_id(97935);
  script_osvdb_id(
    155944,
    155945,
    155946,
    155947
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCur29331");
  script_xref(name:"CISCO-BUG-ID", value:"CSCut47751");
  script_xref(name:"CISCO-BUG-ID", value:"CSCut50727");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu76493");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170419-energywise");

  script_name(english:"Cisco IOS XE EnergyWise DoS (cisco-sa-20170419-energywise)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by multiple buffer overflow
conditions due to improper parsing of EnergyWise packets. An
unauthenticated, remote attacker can exploit these, by sending
specially crafted IPv4 EnergyWise packets to the device, to cause a
denial of service condition. Note that IPv6 packets cannot be used to
exploit these issue and that the EnergyWise feature is not enabled by
default on Cisco XE devices.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170419-energywise
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d2ebdad");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCur29331");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCut47751");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCut50727");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuu76493");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security
Advisory cisco-sa-20170419-energywise.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/26");

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

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag = 0;

if (
  ver == '3.2.1SG' ||
  ver == '3.2.8SG' ||
  ver == '3.3.1SG' ||
  ver == '3.4.2SG' ||
  ver == '3.4.1SG' ||
  ver == '3.4.3SG' ||
  ver == '3.4.6SG' ||
  ver == '3.4.8SG' ||
  ver == '3.5.1E' ||
  ver == '3.5.3E' ||
  ver == '3.6.0E' ||
  ver == '3.6.1E' ||
  ver == '3.6.2aE' ||
  ver == '3.6.2E' ||
  ver == '3.6.4E' ||
  ver == '3.6.5E' ||
  ver == '3.6.5aE' ||
  ver == '3.3.1SQ' ||
  ver == '3.7.0E' ||
  ver == '3.7.1E' ||
  ver == '3.7.2E' ||
  ver == '3.7.3E' ||
  ver == '3.8.0E' ||
  ver == '3.18.1SP'
)
{
  flag++;
}

cmds = make_list();
# Check that device is configured with EnergyWise support
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show run | include energywise", "show run | include energywise");
  if (check_cisco_result(buf))
  {
    if ("energywise" >< buf)
    {
      cmds = make_list(cmds, "show run | include energywise");
      flag = 1;
    }
  }
  else if (cisco_needs_enable(buf))
    override = 1;

  if (!flag && !override) audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS XE", ver);
}

if (flag || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : "CSCur29331, CSCut47751, CSCut50727, CSCuu76493",
    cmds     : cmds
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
