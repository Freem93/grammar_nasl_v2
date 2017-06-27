#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92369);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/06 19:52:16 $");

  script_name(english:"Microsoft Windows Time Zone Information");
  script_summary(english:"Report time zone information.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to collect and report time zone information from the
remote host.");
  script_set_attribute(attribute:"description", value:
"Nesssus was able to collect time zone information from the remote
Windows host and generate a report as a CSV attachment.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Incident Response");
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("csv_generator.inc");

exit(0, "This plugin is temporarily disabled");

function display_dword (dword, nox)
{
 local_var tmp;

 if (isnull(nox) || (nox == FALSE))
   tmp = "0x";
 else
   tmp = "";

 return string (tmp,
               toupper(
                  hexstr(
                    raw_string(
                               (dword >>> 24) & 0xFF,
                               (dword >>> 16) & 0xFF,
                               (dword >>> 8) & 0xFF,
                               dword & 0xFF
                              )
                        )
                       )
                );
}

get_kb_item_or_exit("SMB/Registry/Enumerated");

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

if (isnull(hklm))
{
   close_registry();
   audit(AUDIT_REG_FAIL);
}

#HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation
# REG_SZ
# DaylightName
# StandardName
# TimeZoneKeyName
# REG_DWORD
# ActiveTimeBias
# Bias
# DaylightBias
# DynamicDaylightTimeDisabled
# StandardBias
# REG_BINARY
# DaylightStart
# StandardStart
# get_registry_values(handle, items)
key_path = 'SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation\\';

string_values = get_registry_values(handle:hklm, items:make_list(key_path + "DaylightName", key_path + "StandardName", key_path + "TimeZoneKeyName"));

dword_values = get_registry_values(handle:hklm, items:make_list(key_path + "ActiveTimeBias", key_path + "Bias", key_path + "DaylightBias", key_path + "DynamicDaylightTimeDisabled", key_path + "StandardBias"));

binary_values = get_registry_values(handle:hklm, items:make_list(key_path + "DaylightStart", key_path + "StandardStart"));

RegCloseKey(handle:hklm);

close_registry();

timezone_data = make_list();
foreach key(keys(string_values))
{
  timezone_data[max_index(timezone_data)] = make_array("name", 'HKLM\\' + key, "value", string_values[key]);
}

foreach key(keys(dword_values))
{
  timezone_data[max_index(timezone_data)] = make_array("name", 'HKLM\\' + key, "value", display_dword(dword:dword_values[key]));
}

foreach key(keys(binary_values))
{
  timezone_data[max_index(timezone_data)] = make_array("name", 'HKLM\\' + key, "value", hexstr(binary_values[key]));
}

if (max_index(timezone_data) > 0)
{
  timezone_data_header = header_from_list(list:make_list("name", "value"));
  csv = generate_csv(header:timezone_data_header, data:timezone_data);
  attachments = make_list();
  attachments[0] = make_array();
  attachments[0]["name"] = "time_zone_info.csv";
  attachments[0]["value"] = csv;
  attachments[0]["type"] = "text/csv";

  report = 'Time zone information attached.';
  security_report_with_attachments(port:0, level:0, extra:report, attachments:attachments);
}
else
{
  exit(0, "No time zone information found.");
}
