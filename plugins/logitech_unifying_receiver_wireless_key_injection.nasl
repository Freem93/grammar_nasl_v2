#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88905);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/07/21 13:58:10 $");

  script_osvdb_id(134983);
  script_xref(name:"CERT", value:"981271");

  script_name(english:"Logitech Unifying Receiver Key Injection (MouseJack)");
  script_summary(english:"Checks if a USB device has been used on the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has used a wireless USB keyboard device that is
potentially affected by a wireless key injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has used a Logitech Unifying Receiver wireless
USB device with firmware version 12.01 or 12.03. It is potentially
affected by a wireless key injection vulnerability that allows a
physically local attacker to send keystrokes to the host.

Note that Nessus cannot determine when the USB device was last used on
the remote host, just that is has been previously used.");
  script_set_attribute(attribute:"see_also", value:"https://secure.logitech.com/en-us/promotions/6072");
  script_set_attribute(attribute:"see_also", value:"https://www.mousejack.com/");
  script_set_attribute(attribute:"solution", value:
"Unplug the Logitech Unifying Receiver wireless USB device from the
host until the vendor issues a firmware update or patch.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:logitech:unifying_receiver");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_historic_usb_device_usage.nasl");
  script_require_keys("Settings/ParanoidReport", "Host/EnumUSB");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

get_kb_item_or_exit("Host/EnumUSB");

instances = get_kb_list_or_exit("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Enum/USB/VID_046D&PID_C52B/*/HardwareID");

vuln = FALSE;
report = '\nPreviously used vulnerable Logitech Unifying Receiver USB devices :\n';
firmware_version = UNKNOWN_VER;

foreach key (keys(instances))
{
  hwid = get_kb_item(key);
  if (empty_or_null(hwid)) continue;
  key = key - "HardwareID" + "LocationInformation";
  loc = get_kb_item(key);
  if (empty_or_null(loc)) loc = "unknown";

  if (strlen(hwid) > 28)
    firmware_version = substr(hwid, 26, 27) + "." + substr(hwid, 28, 29);
  else
    firmware_version = UNKNOWN_VER;

  if (firmware_version == "12.01" ||
      firmware_version == "12.03")
  {
    report += '\n  Hardware ID          : ' + hwid + '\n';
    report += '  Location information : ' + loc + '\n';
    report += '  Firmware version     : ' + firmware_version + '\n';
    vuln = TRUE;
  }
}

if (!vuln)
  audit(AUDIT_DEVICE_NOT_VULN, "The Logitech Unifying Receiver USB device on the remote host", firmware_version);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
