#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88934);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/02/24 21:47:17 $");

  script_xref(name:"CERT", value:"981271");

  script_name(english:"USB Device Wireless Key Injection or DoS (MouseJack)");
  script_summary(english:"Checks if a USB device has been used on the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has used a wireless USB keyboard device that is
potentially affected by a wireless key injection or denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has used a wireless USB keyboard device that
is potentially affected by a key injection or denial of service
vulnerability that allows a physically local attacker to send
keystrokes to the host.

Note that Nessus cannot determine when the USB device was last used on
the remote host, just that is has been previously used.");
  script_set_attribute(attribute:"see_also", value:"https://www.mousejack.com/");
  script_set_attribute(attribute:"solution", value:
"Unplug the wireless USB keyboard device from the host until the
vendor issues a firmware update or patch.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

vuln_usb_ids = make_list(
  # Key Injection
  "VID_04F2&PID_0976",
  "VID_046D&PID_C52B",
  "VID_413C&PID_2501",
  "VID_04B4&PID_0060",
  "VID_03F0&PID_D407",
  "VID_17EF&PID_6071",
  "VID_045E&PID_0745",
  "VID_045E&PID_07B2",
  "VID_045E&PID_07A5",
  # DoS
  "VID_17EF&PID_6060",
  "VID_17EF&PID_6032",
  "VID_17EF&PID_6022"
);

vuln = FALSE;
report = '\nPreviously used vulnerable USB devices :\n';

foreach usb_id (vuln_usb_ids)
{
  instances = get_kb_list("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Enum/USB/" + usb_id + "/*/HardwareID");
  foreach key (keys(instances))
  {
    hwid = get_kb_item(key);
    if (empty_or_null(hwid)) hwid = usb_id;
    key = key - "HardwareID" + "LocationInformation";
    loc = get_kb_item(key);
    if (empty_or_null(loc)) loc = "unknown";
    report +=
      '\nHardware ID          : ' + hwid + '\n' +
      'Location information : ' + loc + '\n';
    vuln = TRUE;
  }
}

if (!vuln)
  audit(AUDIT_HOST_NOT, "affected");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
