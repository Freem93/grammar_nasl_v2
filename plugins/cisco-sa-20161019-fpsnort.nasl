#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94469);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/26 15:50:24 $");

  script_cve_id("CVE-2016-6439");
  script_bugtraq_id(93787);
  script_osvdb_id(146038);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20161019-fpsnort");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux61630");
  script_xref(name:"IAVA", value:"2016-A-0301");

  script_name(english:"Cisco Firepower Packet Inspection Engine HTTP Stream DoS");
  script_summary(english:"Checks the version of Cisco Firepower System.");

  script_set_attribute(attribute:"synopsis", value:
"The packet inspection software on the remote host is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Firepower System running on the remote host is
affected by a denial of service vulnerability in the packet inspection
engine due to improper handling of certain HTTP packet streams. An
unauthenticated, remote attacker can exploit this, via a specially
crafted HTTP packet stream, to cause the Snort process to restart,
allowing traffic inspection to be bypassed or traffic to be dropped.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161019-fpsnort
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d8348603");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Firepower System version 5.4.0.7 / 5.4.1.6  / 6.0.1 /
6.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/10/19");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/02");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:firepower_management_center");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_firepower_version.nasl");
  script_require_keys("Host/Cisco/firepower/Version");

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");

version = get_kb_item_or_exit("Host/Cisco/firepower/Version");

# strip out build
item = eregmatch(pattern:"^([0-9.]+)($|-)", string:version);
if(!isnull(item))
  version = item[1];
else audit(AUDIT_VER_FORMAT, version); 

flag = 0;
fixed_version = "";

if (version == "5.4.0.6")
{
  flag++;
  fixed_version = "5.4.0.7";
}
else if (version == "5.4.1.5")
{
  flag++;
  fixed_version = "5.4.1.6";
}

else if (version == "6.0" || version == "6.0.0.1")
{
  flag++;
  fixed_version = "6.0.1/6.1.0";
}

if (flag)
{
  report =
    '\n  Installed Version : ' + version +
    '\n  Fixed version     : ' + fixed_version;
  security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_DEVICE_NOT_VULN, "Cisco Firepower System", version);
