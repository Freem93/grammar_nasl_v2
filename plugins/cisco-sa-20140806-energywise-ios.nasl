#TRUSTED 5f2cd4ef6881c393ec2718426267efe15171db068a58db90c3e23e6487a2714b6f0e77ae451e95721bacc4c4ebf984a61616970a48ec203d05dc4ab1ebcecb0f56a536aa1d35ddc980d9ff506bf33d50d92acf19f64a639b4db50cf209c2e443194014d3a9d3fd63d26e52e1ad665d62f6661ec855ad4ca0420b3749d90394aa7d51c91244564074bc2d35950010ea3d469dd6e3d5972aefdffc86c421be3daef012340a9fb5166b2618edfad325c76e24cd617cf56cf171fbe83e0ff7e527c2e31a9e7fee549b7f902bfc1fd21ca4aaa57e9a50221db636f4d15cc9d6c1400163c64ca003d401f58a44468cbff39e836b543b192b366cc5e6b582a28bc411c3f77e5bb60746f7deecd868d7745b98b2842ce1fb2a17c5fc5a5200b385befec84ac82d11d319fc821b4e6643d00a5c35a703c0f637bdaa7398a17576a9ca1f325511397c05ea18a13931e9dfe1f4f437d0ceb5e696e84fdd6f009d451f855ca292411f64521532d2ea4ace24db15e8bddea2229a70e11cafb571140274a992abd1a9643eaf2d4383430fe591270d61314320841b151a3f5038f71a65cc5d275e221c33630bdd64dcfe40659141c9696b214c4891569c47c0bdb118fa6efc1b16b067643652b5c62bd241a7a47119bf288cfee20317e661eb487b75d8bb520b0a986a35a5b59b345653d28f656dc920960f5d7e9937d0e2b03dc3562d4cdea074
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77153);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-3327");
  script_bugtraq_id(69066);
  script_osvdb_id(109861);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup52101");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140806-energywise");

  script_name(english:"Cisco IOS Software EnergyWise DoS (cisco-sa-20140806-energywise");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS
running on the remote host is affected by a denial of service
vulnerability in EnergyWise module.

The issue exists due to improper handling of specially crafted
EnergyWise packets. An unauthenticated, remote attacker could exploit
this issue to cause a device reload.

Note that this issue only affects hosts with EnergyWise enabled.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140806-energywise
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3e4f4ee3");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35091");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in the Cisco Security Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/12");

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

flag = 0;
override = 0;

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Check for vuln version
if ( ver == '15.2E' ) flag++;
if ( ver == '15.2(2)E' ) flag++;
if ( ver == '15.2(1)E3' ) flag++;
if ( ver == '15.2(1)E2' ) flag++;
if ( ver == '15.2(1)E1' ) flag++;
if ( ver == '15.2(1)E' ) flag++;
if ( ver == '15.1SY' ) flag++;
if ( ver == '15.1SG' ) flag++;
if ( ver == '15.1(2)SY3' ) flag++;
if ( ver == '15.1(2)SY2' ) flag++;
if ( ver == '15.1(2)SY1' ) flag++;
if ( ver == '15.1(2)SY' ) flag++;
if ( ver == '15.1(2)SG4' ) flag++;
if ( ver == '15.1(2)SG3' ) flag++;
if ( ver == '15.1(2)SG2' ) flag++;
if ( ver == '15.1(2)SG1' ) flag++;
if ( ver == '15.1(2)SG' ) flag++;
if ( ver == '15.1(1)SY3' ) flag++;
if ( ver == '15.1(1)SY2' ) flag++;
if ( ver == '15.1(1)SY1' ) flag++;
if ( ver == '15.1(1)SY' ) flag++;
if ( ver == '15.1(1)SG2' ) flag++;
if ( ver == '15.1(1)SG1' ) flag++;
if ( ver == '15.1(1)SG' ) flag++;
if ( ver == '15.0SE' ) flag++;
if ( ver == '15.0EZ' ) flag++;
if ( ver == '15.0EX' ) flag++;
if ( ver == '15.0EK' ) flag++;
if ( ver == '15.0EJ' ) flag++;
if ( ver == '15.0EH' ) flag++;
if ( ver == '15.0ED' ) flag++;
if ( ver == '15.0(2)SE6' ) flag++;
if ( ver == '15.0(2)SE5' ) flag++;
if ( ver == '15.0(2)SE4' ) flag++;
if ( ver == '15.0(2)SE3' ) flag++;
if ( ver == '15.0(2)SE2' ) flag++;
if ( ver == '15.0(2)SE1' ) flag++;
if ( ver == '15.0(2)SE' ) flag++;
if ( ver == '15.0(2)EZ' ) flag++;
if ( ver == '15.0(2)EX6' ) flag++;
if ( ver == '15.0(2)EX5' ) flag++;
if ( ver == '15.0(2)EX4' ) flag++;
if ( ver == '15.0(2)EX3' ) flag++;
if ( ver == '15.0(2)EX2' ) flag++;
if ( ver == '15.0(2)EX1' ) flag++;
if ( ver == '15.0(2)EX' ) flag++;
if ( ver == '15.0(2)EK' ) flag++;
if ( ver == '15.0(2)EJ1' ) flag++;
if ( ver == '15.0(2)ED1' ) flag++;
if ( ver == '15.0(1)SE3' ) flag++;
if ( ver == '15.0(1)SE2' ) flag++;
if ( ver == '15.0(1)SE1' ) flag++;
if ( ver == '15.0(1)SE' ) flag++;
if ( ver == '12.2SE' ) flag++;
if ( ver == '12.2EZ' ) flag++;
if ( ver == '12.2EY' ) flag++;
if ( ver == '12.2EX' ) flag++;
if ( ver == '12.2(60)EZ4' ) flag++;
if ( ver == '12.2(60)EZ3' ) flag++;
if ( ver == '12.2(60)EZ2' ) flag++;
if ( ver == '12.2(60)EZ1' ) flag++;
if ( ver == '12.2(60)EZ' ) flag++;
if ( ver == '12.2(58)SE2' ) flag++;
if ( ver == '12.2(58)SE1' ) flag++;
if ( ver == '12.2(58)SE' ) flag++;
if ( ver == '12.2(58)EY2' ) flag++;
if ( ver == '12.2(58)EY1' ) flag++;
if ( ver == '12.2(58)EY' ) flag++;
if ( ver == '12.2(58)EX' ) flag++;
if ( ver == '12.2(55)EX3' ) flag++;

# Check that EnergyWise is running
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config",
                              "show run | include energywise");
  if (check_cisco_result(buf))
  {
    if (
      preg(multiline:TRUE, pattern:"energywise\s+domain", string:buf)     ||
      preg(multiline:TRUE, pattern:"energywise\s+management", string:buf) ||
      preg(multiline:TRUE, pattern:"energywise\s+endpoint", string:buf)
    ) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCup52101' +
      '\n  Installed release : ' + ver +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(0);
}
else audit(AUDIT_HOST_NOT, "affected");
