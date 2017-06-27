#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69019);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/06/19 00:03:29 $");

  script_cve_id("CVE-2013-1236");
  script_bugtraq_id(59879);
  script_osvdb_id(93410);
  script_xref(name:"IAVB", value:"2013-B-0055");

  script_name(english:"Cisco TelePresence Supervisor MSE 8050 TCP Connection Request Saturation Remote DoS");
  script_summary(english:"Checks software version");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to version information obtained by examining its FTP service
banner, the remote Cisco TelePresence device is affected by a remote
denial of service vulnerability that can be triggered by overwhelming
the device with TCP connection requests.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130515-mse
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e209f42");
  script_set_attribute(attribute:"solution", value:"Upgrade software to version 2.3(1.31) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_supervisor_mse_8050");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_supervisor_mse_detect.nbin");
  script_require_keys("cisco/supervisor_mse/8050");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");

version = get_kb_item_or_exit("cisco/supervisor_mse/8050");

item = eregmatch(pattern: "^([0-9.]+)(\(([0-9.]+)\))?$", string: version);
if (isnull(item)) exit(1, "Failed to parse version string.");

vuln = FALSE;

if (ver_compare(ver:item[1], fix:"2.3", strict:FALSE) == -1) vuln = TRUE;

if (item[1] == "2.3")
{
  if (isnull(item[3])) audit(AUDIT_VER_NOT_GRANULAR, "Cisco TelePresence Supervisor MSE 8050", version);

  if (ver_compare(ver:item[3], fix:"1.31", strict:FALSE) == -1)  vuln = TRUE;
}

if (vuln)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : 2.3(1.31)\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco TelePresence Supervisor MSE 8050 software", version);
