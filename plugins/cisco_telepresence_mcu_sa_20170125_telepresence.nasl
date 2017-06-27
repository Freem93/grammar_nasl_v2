#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97021);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/09 15:07:53 $");

  script_cve_id("CVE-2017-3792");
  script_bugtraq_id(95787);
  script_osvdb_id(150929);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu67675");
  script_xref(name:"IAVA", value:"2017-A-0029");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170125-telepresence");

  script_name(english:"Cisco TelePresence MCU Fragmented Packets Reassembly RCE");
  script_summary(english:"Checks the software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to the self-reported version, the remote Cisco TelePresence
Multipoint Control Unit (MCU) device is affected by a buffer overflow
condition that occurs when reassembling fragmented IPv4 and IPv6
packets due to improper size validation. An unauthenticated, remote
attacker can exploit this issue, by sending specially crafted
fragmented packets to a port receiving content in Passthrough content
mode, to cause a denial of service condition or the execution of
arbitrary code.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170125-telepresence
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?55c626f9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuu67675");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuu67675.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_mcu_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_mcu_detect.nasl");
  script_require_keys("Cisco/TelePresence_MCU/Version", "Cisco/TelePresence_MCU/Device");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

device   = get_kb_item_or_exit("Cisco/TelePresence_MCU/Device");
version  = get_kb_item_or_exit("Cisco/TelePresence_MCU/Version");
fullname = "Cisco TelePresence "+device;

# TelePresence MCU 5300 Series
# TelePresence MCU MSE 8510
# TelePresence MCU 4500 Series
if (
  device !~ "MCU 53\d\d" &&
  "MSE 8510" >!< device &&
  device !~ "MCU 45\d\d"
)
audit(AUDIT_DEVICE_NOT_VULN, fullname);

fix = FALSE;
note = "";

# 4.2 and earlier - Not affected
# 4.3 - Affected; migrate to 4.5(1.89)
# 4.4 - Affected; migrate to 4.5(1.89)
# 4.5 - Affected; migrate to 4.5(1.89)
if (version =~ "^4\.[345](\.|\(|$)")
  fix = "4.5(1.89)";

# 4.3 releases prior to 4.3(1.68) are not affected
if (version =~ "^4\.3(\.|\(|$)")
{
  if (cisco_gen_ver_compare(a:version, b:"4.3(1.68)") < 0)
    fix = FALSE;
}

if (fix && cisco_gen_ver_compare(a:version, b:fix) == -1)
{

  # only vulnerable when configured in Passthrough content mode
  if (report_paranoia < 2) audit(AUDIT_PARANOID);

  # no fix for the TelePresence MCU 4500 platform as that platform has reached the end-of-software maintenance milestone
  if (device =~ "MCU 45\d\d")
  {
    fix = "N/A";
    note =  '\nCisco TelePresence MCU 4500 series devices have reached' +
            '\nend of life and no fix will be provided.';
  }

  order = make_list("Device", "Installed version", "Fixed version");
  report = make_array(
    order[0], fullname,
    order[1], version,
    order[2], fix
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  if (!empty_or_null(note)) report += note;

  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_VER_NOT_VULN, fullname, version);
