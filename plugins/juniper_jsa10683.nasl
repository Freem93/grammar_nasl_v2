#TRUSTED 3fb59d5f596567ad1df28d76bda8b8519ef7b342e49823b6ebf9862dd8028aeaf6aeb659b3bf3af5e977c62b1db72edda37e2ee650372b828289ca9ae6103bd41ffa5894c7a0daebaab5ccf57249131aa13b3680a4771e0dcad1c3483f3e1ca76c9d47d353cac462ce0192ebda56aaefdb802e56c8a372023c0fe027b00df1c12780a895dc5c716e7e21f7f39dafc685e8f3bab33ca4088b4cd4f05cd4796da740d38890d7bc41cffc354366c6f77d308298aeaa01b3944a386fee268bbd9b6bf7f06e558d15f339b529cf0190b6a5390e520f0eb81e26d3a3febdb104484d023b64a36ea26c130c0e0700bd710f87f8fe47f076f366e524d771193e18dd20ca3246d631eb568e838507cd00bc0e0ffbbcefb2bdb459573f1197d8eb00d98d40060d065e55ce3fdd5ac128480ac26140c3b0358a63a30e9e33c6246c00e27241da6f7d82153d37f215eb6686c53247ac831aef239c47f8ba5f676409ad9de962fa26ecd4dec4aaa875283b9e19cc019847a5fe2928582f19bacb6aeccbee64bbe61acb12da83a21ad376dfbfff8ff418892e1fa35226bf115347466a36885a682ca4c9dd6148368fbf24a3a543a3370ec7e2531d2c0ec5e217923311a7f2cb2622799fc2712c0d5893045b77f16d6760889fc489bfff9535b9b42df8da2378aef3c77420ca4bdfdcf95292c9a929feed19f5ce24ccb6f216819a9a721c19ff60
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85225);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/12/24");

  script_cve_id("CVE-2015-3007");
  script_bugtraq_id(75718);
  script_osvdb_id(124293);
  script_xref(name:"JSA", value:"JSA10683");

  script_name(english:"Juniper Junos SRX Series 'set system ports console insecure' Local Privilege Escalation (JSA10683)");
  script_summary(english:"Checks the Junos version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos SRX Series device is affected by a privilege escalation
vulnerability related to the 'set system ports console insecure'
feature. A local attacker can exploit this vulnerability by using
access to a console port to gain full administrative privileges.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10683");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10683.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

if (ver =~ "^12.1X46-D([0-9]|1[0-4])$") audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();
fixes['12.1X46'] = '12.1X46-D35';
fixes['12.1X47'] = '12.1X47-D25';
fixes['12.1X48'] = '12.1X48-D15';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set system ports console insecure";
  if (!preg(string:buf, pattern:pattern, multiline:TRUE))
    audit(AUDIT_HOST_NOT,
      "affected because the 'set system ports console insecure' feature is not enabled");
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
