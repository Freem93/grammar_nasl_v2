#TRUSTED 8940f0f674a0bf3201fc14d131a5d7de6accf6fabe63d948776abda814c3b87eca491ade151395a10c386022e16a54ffc00ada5b83bc317be63af72ec7d0c3cb652a357d9a8ba3293aac2c687656c5d3afe1ce871406e5aeb000c846a8652aaf7f84ab9c03b791d8d7e1a0d0b32b7b2201dc42b779c0b3bcb46fbff31e52a8e0809ff3ddc9709fb037a1073461da978cb2d67284e6b97301d35304b7edf70d4eddd337238c5105378730b4a0fa20e0bee2efc71d12d338774c5ca11e812266216b629d85a0480dbad378e03d42260d5c6ad5a1fabb08d567f1f519b39ad04e3d425e3c88ad8f581eff8d27143cdc486157ce3909a0b6d97b7f360bea0d48efe32b46157af884671679f377fa68c0f1869a2aa6c5f67614591d3609e0ed5f3c026a771259754d25c31cb8235f6f8b841087b52a2d2b1289c46a91c5431a01439b6cb8dac49146da913ed7a15f4780bffd5cdc1d2516fc2afb77eb48ed56d59829018ff98e81d86eb6c3bb9b5f755a15108a334ec778cb359884026cc84b00d1fc1772d7fce1a743f1e9492afbcb611aba64466b825709c47105fe29bf2a78fb483559477d929f9eb07411cf3c0021720f262dc92cda1a96bd60ee6e848b4433e863cab663fca3d6a7e41983be14ddc2758973d5860f4fb6969c2675dadef480dacdb56f140007ca54dea074484db17fef214e92a311c0b78fb940b5b3044ad433
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70894);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/05/24");

  script_cve_id("CVE-2013-5522");
  script_bugtraq_id(63342);
  script_osvdb_id(98918);
  script_xref(name:"CISCO-BUG-ID", value:"CSCue92286");

  script_name(english:"Cisco Catalyst 3750-X Series Switch Default Credentials Vulnerability (CSCue92286)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is running a vulnerable IOS version.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device potentially contains an issue which, due to
default credentials on the Cisco Service Module, could allow a local
attacker to gain unauthorized root access.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-5522
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ff9a6e4a");
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced in Cisco Bug Id CSCue92286.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/13");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Host/Cisco/IOS/Model", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

flag = 0;
override = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
if ( version == '15.0(2)SE1' ) flag++;

# check model
model = get_kb_item("CISCO/model");
if (model)
{
  if (model !~ "catalyst3750") audit(AUDIT_HOST_NOT, "affected");
}
else
{
  model = get_kb_item_or_exit("Host/Cisco/IOS/Model");
  if (model !~ "3750[Xx]") audit(AUDIT_HOST_NOT, "affected");
}

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
  flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_switch_service-modules", "show switch service-modules", 1);
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"\s+\d+\s+OK\s+", string:buf)) { flag = 1; }
    }
    else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }

  }
}

if (flag)
{
  report =
    '\n  Cisco Bug ID        : CSCue92286' +
    '\n    Installed release : ' + version + '\n';

  security_warning(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
