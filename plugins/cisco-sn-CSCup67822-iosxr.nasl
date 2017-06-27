#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82473);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_cve_id("CVE-2015-0672");
  script_bugtraq_id(73318);
  script_osvdb_id(119892);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup67822");

  script_name(english:"Cisco IOS XR DHCPv4 Message Saturation DoS");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco ASR 9000 device is running a version of Cisco IOS XR
that is affected by a denial of service vulnerability due to improper
processing of crafted DHCP messages. An unauthenticated, remote
attacker can exploit this issue by sending a large amount of crafted
DHCP messages to a targeted interface to cause the device to stop
responding, resulting in a denial of service condition.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=38006");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCup67822");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug ID CSCup67822.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

# Check version
# 5.2.2 only release listed as known affected
version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
if (version !~ "^5\.2\.2$") audit(AUDIT_HOST_NOT, "affected");

# Check model
model = get_kb_item("CISCO/model");
if(!isnull(model) && model !~ "ciscoASR9[0-9]{3}") audit(AUDIT_HOST_NOT, "ASR 9000 series");
# First source failed, try another source
if (isnull(model))
{
  model = get_kb_item_or_exit("Host/Cisco/IOS-XR/Model");
  if ("ASR9K" >!< model) audit(AUDIT_HOST_NOT, "ASR 9000 series");
}

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : CSCup67822' +
    '\n  Installed release : ' + version +
    '\n  Model             : ' + model   +
    '\n';
  security_warning(port:0, extra:report);
}
else security_warning(port:0);
