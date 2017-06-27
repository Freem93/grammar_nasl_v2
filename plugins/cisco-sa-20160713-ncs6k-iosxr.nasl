#TRUSTED 7009b3383dfde45268020e8fa30c9c0e7ae2d5b36d1e9c05cea7d30eb1b9eb77913d49bd8f921e09238ba0092054ae5723472ee2cce8c1c799306eea0886bf83145860c14b39b7c4dcbe08a2f24d43c23858d89c543acb973d327d231c60789722fce3687050382f949daea9e589520e2c3229905ef37ccbfdd1fb44058a80a313d4f1e49c610b34cec8a4f1d5ec2e8439cd25265ef948a99f1191c43806ff0a28da7ebb187b9febaa3a7ceb00d2438b6ec4594a796af29c2674714cf324ab479baeb2e443f2748b95d9ba034fff526256b5131ae678281f3c0989abd1c76201f4498dd438e28d409910bf413d3e8885111410dc19356b46292696cb2c52fcc5b3b673e8280d137eba215e6a4f3af10e59cff89617d009dedd2db8851ddf55134cf07d5ecc1927c5aef4bfa717470ad29ac10807a2905488b7226504c352f9fd3053b2c3fa28ed56f7892ba0ea4d52aa6ba3412dada9fd3f115164a433870a6f072ebc64cd8d6789aeed88604afc02f81204cf3a8976f995fabdb6fd52c09303745b2053c554bcd85101da0e84656b7a97468cdd9ba3acba2755802401279d301fe6c69c181e6c1844e9d393ac6bdbe6a8643ba3f6e4603de085ea4b0272f5823fca2ce1074ba985f5047da5390b7371cbfacdbb130bcdca81b4c222423672daa5eee1fa736209296ed78dcf4872e0428663a83450f284b5dbb0ef9137706843
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93563);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/09/16");

  script_cve_id("CVE-2016-1426");
  script_bugtraq_id(91748);
  script_osvdb_id(141465);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160713-ncs6k");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux76819");

  script_name(english:"Cisco IOS XR NCS 6000 Packet Timer Leak DoS (cisco-sa-20160713-ncs6k)");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco IOS XR running on the remote NCS 6000 device is
affected by a denial of service vulnerability due to improper
management of system timer resources. An unauthenticated, remote
attacker can exploit this, via numerous management connections to the
affected device, to consume resources, resulting in a nonoperational
state and eventual reload of the Route Processor.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160713-ncs6k
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87b0a91e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCux76819");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco advisory
cisco-sa-20160713-ncs6k.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");
  script_require_ports("CISCO/model", "Host/Cisco/IOS-XR/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version  = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
model = get_kb_item("CISCO/model");
if (model)
{
  if (model !~ "^cisco([Nn]cs|NCS)-?(600[08]|6k)")
    audit(AUDIT_HOST_NOT, "an affected model");
}
else
{
  model = get_kb_item_or_exit("Host/Cisco/IOS-XR/Model");
  if ("NCS6K"    >!< model &&
      "NCS6008"  >!< model &&
      "NCS-6000" >!< model &&
      "NCS-6008" >!< model
     )
    audit(AUDIT_HOST_NOT, "an affected model");
}

# Affected versions include :
#  - 5.0.0-5.0.1
#  - 5.1.0-5.1.3
#  - 5.2.0-5.2.5
if (version !~ "^5\.(0\.[01]|1\.[0-3]|2\.[0-5])([^0-9]|$)")
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco IOS XR', version);

missing_pie  = '';

# Cisco SMUs per version (where available)
pies = make_array(
  '5.0.1', 'ncs6k-5.0.1.CSCux76819',
  '5.2.1', 'ncs6k-5.2.1.CSCux76819',
  '5.2.3', 'ncs6k-5.2.3.CSCux76819',
  '5.2.4', 'ncs6k-5.2.4.CSCux76819',
  '5.2.5', 'ncs6k-5.2.5.CSCux76819'
);

if (get_kb_item("Host/local_checks_enabled"))
{
  # Check for patches; only specific versions
  if (!isnull(pies[version]))
  {
    buf = cisco_command_kb_item("Host/Cisco/Config/show_install_package_all", "show install package all");
    if (check_cisco_result(buf))
    {
      if (pies[version] >!< buf)
        missing_pie = pies[version];
      else audit(AUDIT_HOST_NOT, "affected because patch "+pies[version]+" is installed");
    }
    else if (cisco_needs_enable(buf)) override = TRUE;
  }

  # Check if SSH, SCP, or SFTP is configured for management access
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if ("ssh server v2" >!< buf)
      audit(AUDIT_HOST_NOT, "affected because SSH / SCP / and SFTP are not enabled for management access");
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

security_report_cisco(
  port     : 0,
  severity : SECURITY_HOLE,
  override : override,
  version  : version,
  bug_id   : 'CSCux76819',
  cmds     : make_list('show running-config'),
  pie      : missing_pie
);
