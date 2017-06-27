#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70079);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/05/24 04:37:33 $");

  script_cve_id("CVE-2013-1176");
  script_bugtraq_id(59272);
  script_osvdb_id(92511);

  script_name(english:"Cisco TelePresence DSP Card Crafted RTP Packet H.264 Bit Stream Handling DoS");
  script_summary(english:"Checks the software version on the remote device");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is affected by a denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According the self-reported version of the remote Cisco TelePresence
MCU or MCU MSE device, it is affected by a denial of service
vulnerability due to a flaw in the DSP card on these devices that can be
triggered by sending specially crafted RTP packets."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130417-tpi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da092f32");
  script_set_attribute(attribute:"solution", value:"Upgrade the software on the device to version 4.3(2.30) or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_mcu_mse_series_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_mcu_detect.nasl");
  script_require_keys("Cisco/TelePresence_MCU/Version");
  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

device = get_kb_item_or_exit("Cisco/TelePresence_MCU/Device");
version = get_kb_item_or_exit("Cisco/TelePresence_MCU/Version");

if (version !~ "^[0-9.()]+$") exit(0, 'The version string is invalid or not applicable.');

fix = '';
found_affected_device = FALSE;

if (
  device =~ " 45[012][05]($|[ \n\r])" || # 4500 series
  device =~ " 4501($|[ \n\r])" ||
  device =~ " MSE 8510($|[ \n\r])"
)
{
  found_affected_device = TRUE;

  if (cisco_gen_ver_compare(a:version, b:'4.3(2.30)') == -1) fix = "4.3(2.30)";
}

if (!found_affected_device) exit(0, "The remote TelePresence device is not affected.");

if (fix != '')
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
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco TelePresence", version);
