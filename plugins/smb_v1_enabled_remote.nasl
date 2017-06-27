#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96982);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/16 23:55:20 $");

  script_osvdb_id(151058);

  script_name(english:"Server Message Block (SMB) Protocol Version 1 Enabled (uncredentialed check)");
  script_summary(english:"Checks if SMBv1 is enabled via network.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host supports the SMBv1 protocol.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host supports Server Message Block Protocol
version 1 (SMBv1). Microsoft recommends that users discontinue the use
of SMBv1 due to the lack of security features that were included in
later SMB versions. Additionally, the Shadow Brokers group reportedly
has an exploit that affects SMB; however, it is unknown if the exploit
affects SMBv1 or another version. In response to this, US-CERT
recommends that users disable SMBv1 per SMB best practices to mitigate
these potential issues.");
  script_set_attribute(attribute:"see_also", value:"https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/kb/2696547");
  # https://www.us-cert.gov/ncas/current-activity/2017/01/16/SMB-Security-Best-Practices
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8dcab5e4");
  # http://www.theregister.co.uk/2017/01/18/uscert_warns_admins_to_kill_smb_after_shadow_brokers_dump/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?36fd3072");
  # https://www.riskbasedsecurity.com/2016/08/the-shadow-brokers-lifting-the-shadows-of-the-nsas-equation-group/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c7e0cf3");
  script_set_attribute(attribute:"solution", value:
"Disable SMBv1 according to the vendor instructions in Microsoft
KB2696547. Additionally, block SMB directly by blocking TCP port 445
on all network boundary devices. For SMB over the NetBIOS API, block
TCP ports 137 / 139 and UDP ports 137 / 138 on all network boundary
devices.");
  script_set_attribute(attribute:"risk_factor", value: "None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/SMBv1_is_supported");
  script_require_ports(139, 445);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

smbv1_is_supported = get_kb_item_or_exit("SMB/SMBv1_is_supported");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (smbv1_is_supported)
{
  report = '\n' +
           'The remote host supports SMBv1.' +
           '\n';
  security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
}
else audit(AUDIT_HOST_NOT, 'affected');
