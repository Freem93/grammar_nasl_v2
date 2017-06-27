#TRUSTED 1298b96d4234724afee29ed720f81707b479bcf6657ab848a5ce453819919100f5b81c65e81aa28a07b33ce4d31548dddf9c7d854466349235855e3460ce4b61ddc38a1be4edaff32ec415e2de40e1332977755329301f49fa57f352ab45d98631db88e675f7f62181349db8d1328799e5a06598a97fe80375f60860fb04c1c60a824c65b5e7dd01bfb094b63936dedc7417990fe23c3a851adddb80c524f1df4d4a34b07d630a0c30a49d1f6121994946a98c658e058ee3d352b439a7cd5cb7db35dd2777e78dd0781ff9d0ae6b1fcbca047e1e2aa6adacca453c5075b434000cfc6dc5cac53b48ddff00b99e06f5166174f7796b70b4a22e0a20bb7fffdaebae9b46c3d4c9fa4320139a4688f0570bcb4821f68e9543464b58608675959ea71b9d8ced4baccbf17e0cfaded02d78c405a9c7874b7b961f1c8d121f6ac10e03c1057a730f0bd9da9d35897ce9f011fc9de7ec23fc46882b531efb6d10ca40ca92ffbea9264f9e88bc6592ba674a7f5691b6c0db43a26ea5ac9cbe55af424fc1b3ffd552e8f7681b71190cf712483e5ea402eb9d30f491639142c1153a79fa635f8946fb9e6ec13b1c2a62e4af97c5ce8013eec02ba66d3fa58feb2217bfe28666a6eb897545cb23b3df58800f2bd543391326f2e3917d51930a5b2d4166f289efb90b014528f6e52291cabb30fc6aa50837db183c8375fb06c855a61f4f8c68
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78421);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-3825");
  script_bugtraq_id(70366);
  script_osvdb_id(113076);
  script_xref(name:"JSA", value:"JSA10650");

  script_name(english:"Juniper Junos SRX Series ALG 'flowd' Remote DoS (JSA10650)");
  script_summary(english:"Checks the Junos version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos SRX series device is affected by a denial of service
vulnerability related to ALG (Application Layer Gateway). A remote
attacker can exploit this issue by sending a specially crafted SIP
packet to an SRX series device, resulting in a crash of the 'flowd'
process. Repeated exploitation may result in the device becoming
unresponsive.

Note that this issue only affects devices with any ALGs enabled or if
flow-based processing for IPv6 traffic is enabled. All SRX devices,
except for SRX-HE devices, have the SIP ALG enabled by default.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10650");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10650.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

fixes = make_array();
fixes['11.4']    = '11.4R12-S4';
fixes['12.1X44'] = '12.1X44-D40';
fixes['12.1X45'] = '12.1X45-D30';
fixes['12.1X46'] = '12.1X46-D25';
fixes['12.1X47'] = '12.1X47-D10';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
override = TRUE;

# Check if either configurations are enabled 
if (get_kb_item("Host/local_checks_enabled"))
{
  #  Check if flow-based processing for IPv6 traffic is enabled
  vuln     = FALSE;
  buf = junos_command_kb_item(cmd:"show configuration | display set");
  if (buf)
  {
    pattern = "^set security forwarding-options family inet6 mode flow-based";
    if (junos_check_config(buf:buf, pattern:pattern))
      vuln = TRUE;
    override = FALSE;
  }

  #  Check if at least one ALG is enabled
  if (!vuln)
  {
    buf = junos_command_kb_item(cmd:"show security alg status");
    if (buf)
    {
      pattern = ":\s*Enabled$";
      if (preg(string:buf, pattern:pattern, multiline:TRUE))
        vuln = TRUE;
      override = FALSE;
    }
  }

  if (!vuln && !override)
    audit(AUDIT_HOST_NOT,
      'affected because neither flow-based processing for IPv6 traffic is enabled nor at least one ALG is enabled'); 
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
