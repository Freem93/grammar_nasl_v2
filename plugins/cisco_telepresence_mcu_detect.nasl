#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69046);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/05/08 16:39:16 $");

  script_name(english:"Cisco TelePresence Multipoint Control Unit Detection");
  script_summary(english:"Uses FTP and/or SNMP to identify TelePresence MCU devices.");

  script_set_attribute(attribute:"synopsis", value:"Nessus detected a remote video conferencing device.");
  script_set_attribute(attribute:"description", value:
"Nessus determined that the remote host is a multipoint control unit
video teleconferencing device.");
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/ps7060/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_mcu_mse_series_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("snmp_sysDesc.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_require_ports("SNMP/sysDesc", "Services/ftp", 21);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ftp_func.inc");
include("misc_func.inc");

device = '';
version = '';

ftp_port_list = get_kb_list("Services/ftp");
if (isnull(ftp_port_list)) ftp_port_list = make_list();

# add default port (in case we have an empty list)
ftp_port_list = add_port_in_list(list: ftp_port_list, port: 21);

foreach port (ftp_port_list)
{
  banner = get_ftp_banner(port:port);
  if (!banner) continue;

  item = eregmatch(
    pattern:"^.*Welcome to the (Cisco TelePresence|Codian) MCU ([^,]+), version ([0-9.()]+)([^0-9.()]|$)",
    string:banner,
    icase:TRUE
  );
  if (!isnull(item))
  {
    device = "MCU " + item[2];
    version = item[3];

    set_kb_item(name:"Cisco/TelePresence_MCU/Device", value:device);
    set_kb_item(name:"Cisco/TelePresence_MCU/Version", value:version);
    break;
  }
}

desc = get_kb_item("SNMP/sysDesc");

if (
  !isnull(desc) &&
  ("TANDBERG Codec" >< desc || "Cisco Codec" >< desc) &&
  "MCU" >< desc && "SoftW" >< desc)
{
  # we may be able to parse a device from the FTP server,
  # but not the SNMP server. Don't overwrite the device KB
  # with 'unknown' if we found something specific from the FTP
  # banner
  item = eregmatch(pattern:"MCU: ([^\r\n]+)", string:desc);
  if (isnull(item) && device == '') device = 'unknown';
  else device = item[1];

  item = eregmatch(pattern:"SoftW: ([^\r\n]+)", string:desc);
  if (isnull(item)) exit(1, "Error parsing SoftW field from SNMP sysDesc.");

  version = item[1];

  replace_kb_item(name:"Cisco/TelePresence_MCU/Device", value:device);
  replace_kb_item(name:"Cisco/TelePresence_MCU/Version", value:version);
}

if (device == '' || version == '') audit(AUDIT_HOST_NOT, "Cisco TelePresence MCU");

if (report_verbosity > 0)
{
  report = '\n  Device           : ' + device +
           '\n  Software version : ' + version +
           '\n';
  security_note(port:0, extra:report);
}
else security_note(0);
