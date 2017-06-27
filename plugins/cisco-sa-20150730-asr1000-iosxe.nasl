#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85255);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_cve_id("CVE-2015-4291");
  script_osvdb_id(125587);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtd72617");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150730-asr1k");

  script_name(english:"Cisco IOS XE Software for 1000 Series Aggregation Services Routers Fragmented Packet DoS");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco IOS XE software running on the remote Cisco 1000
Series Aggregation Services Router (ASR) is affected by a denial of
service vulnerability in the Embedded Services Processor (ESP) due to
a flaw in handling the reassembly of fragmented IPv4 or IPv6 packets.
A remote, unauthenticated attacker, by sending a crafted sequence of
fragmented packets, can exploit this vulnerability to cause the ESP to
crash, leading to a reload of the affected platform.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCtd72617");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150730-asr1k
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d880662");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=40212");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco Security Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Check model
model = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");
if (('ASR1k' >!< model && model !~ "^ASR\s*10[0-9][0-9]($|[^0-9])"))
  audit(AUDIT_DEVICE_NOT_VULN, "Cisco " + model);

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
fix = NULL; 

if (version =~ "^2\.4\.[0-2]([^0-9]|$)")
  fix = "2.4.3";
else if (version =~ "^2\.[1-3]([^0-9]|$)" || version =~ "^2\.5\.0([^0-9]|$)")
  fix = "2.5.1";

if (isnull(fix)) audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS XE", version);

if (report_verbosity > 0)
{
  report =
  '\n  Cisco bug ID      : CSCtd72617' +
  '\n  Model             : ' + model +
  '\n  Installed release : ' + version +
  '\n  Fixed release     : ' + fix +
  '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
