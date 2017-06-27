#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72184);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_cve_id("CVE-2014-0660");
  script_bugtraq_id(65072);
  script_osvdb_id(102361);
  script_xref(name:"CISCO-BUG-ID", value:"CSCui50360");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140122-isdngw");

  script_name(english:"Cisco TelePresence ISDN Gateway D-Channel DoS");
  script_summary(english:"Checks the software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the remote device is
affected by a vulnerability that could allow an unauthorized user to
cause a denial of service via a specially crafted Q.931 STATUS
message."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140122-isdngw
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d207a21");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=32460");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the appropriate software version per the vendor's
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_isdn_gw");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_isdn_gateway_detect.nbin");
  script_require_keys("Cisco/TelePresence_ISDN_GW/Version");
  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

device = get_kb_item_or_exit("Cisco/TelePresence_ISDN_GW/Device");
version = get_kb_item_or_exit("Cisco/TelePresence_ISDN_GW/Version");

fix = "2.2(1.92)";
found_affected_device = FALSE;
found_vuln_device = FALSE;

if (
  (device == "unknown" && report_paranoia > 1) ||
  "ISDN GW 3241" >< device ||
  "ISDN GW MSE 8321" >< device
)
{
  found_affected_device = TRUE;
  item = eregmatch(pattern:"^([0-9.\(\)]+)", string:version);
  if (!isnull(item) && cisco_gen_ver_compare(a:item[1], b:fix) == -1) found_vuln_device = TRUE;
}
if (!found_affected_device) audit(AUDIT_HOST_NOT,  "affected");

if (found_vuln_device == TRUE)
{
  if (report_verbosity > 0)
  {
    report = '\n  Detected version : ' + version +
             '\n  Fixed version    : ' + fix +
             '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco TelePresence ISDN Gateway software", version);
