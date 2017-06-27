#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69049);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/05/11 04:29:21 $");

  script_cve_id("CVE-2013-3378");
  script_bugtraq_id(60681);
  script_osvdb_id(94438);

  script_name(english:"Cisco TelePresence CVE-2013-3378 Software Malformed SIP Packet Handling Remote DoS");
  script_summary(english:"Checks software version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to the self-reported version returned by the SNMP service on
the remote device, it is affected by a denial of service vulnerability
that can be triggered by sending a specially crafted SIP packet.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130619-tpc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4fd349c7");
  script_set_attribute(attribute:"solution", value:"Upgrade to the appropriate software version per the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_codec");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_e20");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_mxp_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_9000_mxp");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_6000_mxp");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_c_series_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_codec_c40");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_codec_c60");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_codec_c90");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_ex90");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_ex60");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_mcu_detect.nasl");
  script_require_keys("Cisco/TelePresence_MCU/Version");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

device = get_kb_item_or_exit("Cisco/TelePresence_MCU/Device");
version = get_kb_item_or_exit("Cisco/TelePresence_MCU/Version");

fix = '';
found_affected_device = FALSE;

if (
  "TelePresence Profile" >< device || # profile series
  # quick set series
  device =~ " SX20($|[ \n\r])" || device =~ " C20($|[ \n\r])" ||
  # c series
  device =~ " C40($|[ \n\r])" || device =~ " C60($|[ \n\r])" ||
  device =~ " C90($|[ \n\r])" ||
  # MX Series
  device =~ " MX200($|[ \n\r])" || device =~ " MX300($|[ \n\r])" ||
  # EX Series
  device =~ " EX60($|[ \n\r])" || device =~ " EX90($|[ \n\r])"
)
{
  found_affected_device = TRUE;
  item = eregmatch(pattern: "^TC([0-9.]+)", string: version);
  if (
    !isnull(item) && 
    ver_compare(ver:item[1], fix:"6.1", strict:FALSE) == -1
  )
  {
    version = item[0];
    fix = "TC6.1";
  }
  # EX Series Only Additional Checks
  else if (device =~ " EX60($|[ \n\r])" || device =~ " EX90($|[ \n\r])")
  {
    item = eregmatch(pattern: "^TE([0-9.]+)", string: version);
    if (
      !isnull(item) && 
      item[1] =~ "^6(\.0)+"
    )
    {
      version = item[0];
      fix = "TE6.1";
    }
  }
}

# E20
else if (device =~ " E20($|[ \r\n])")
{
  found_affected_device = TRUE;
  item = eregmatch(pattern: "^TE([0-9.]+)", string: version);
  if (
    !isnull(item) && 
    ver_compare(ver:item[1], fix:"4.1.3", strict:FALSE) == -1
  )
  {
    version = item[0];
    fix = "TE4.1.3";
  }
}

if (!found_affected_device) exit(0, "The remote TelePresence Device is not affected.");

if (fix != '')
{
  if (report_verbosity > 0)
  {
    report = '\n  Detected version : ' + version +
             '\n  Fixed version    : ' + fix + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco TelePresence Codecs", version);
