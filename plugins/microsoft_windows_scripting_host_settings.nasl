#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92368);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/06 19:52:16 $");

  script_name(english:"Microsoft Windows Scripting Host Settings");
  script_summary(english:"Report Windows scripting host settings.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to collect and report the Windows scripting host
settings from the remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to collect system and user level Windows scripting
host settings from the remote Windows host and generate a report as a
CSV attachment.");
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
include("charset_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("csv_generator.inc");

exit(0, "This plugin is temporarily disabled");

get_kb_item_or_exit("SMB/Registry/Enumerated");

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

if (isnull(hklm))
{
   close_registry();
   audit(AUDIT_REG_FAIL);
}

hklm_key = 'SOFTWARE\\Microsoft\\Windows Script Host\\Settings';
hklm_values = get_reg_name_value_table(handle:hklm, key:hklm_key);

hklm_wow_key = 'SOFTWARE\\Wow6432Node\\Microsoft\\Windows Script Host\\Settings';
hklm_wow_values = get_reg_name_value_table(handle:hklm, key:hklm_wow_key);

RegCloseKey(handle:hklm);

hku_values = get_hku_key_values(key:"\SOFTWARE\Microsoft\Windows Script Host\Settings", reg_init:FALSE, resolve_sid:FALSE);
if (isnull(hku_values))
{
   close_registry();
   audit(AUDIT_REG_FAIL);
}

close_registry();

hklm_config = make_list();
if (max_index(keys(hklm_values)) > 0)
{
  foreach key(keys(hklm_values))
  {
    hklm_config[max_index(hklm_config)] = make_array("key", 'HKLM\\' + hklm_key + '\\' + key, "value", hklm_values[key]);
  }
}

hklm_wow_config = make_list();
if (max_index(keys(hklm_wow_values)) > 0)
{
  foreach key(keys(hklm_wow_values))
  {
    hklm_wow_config[max_index(hklm_wow_config)] = make_array("key", 'HKLM\\' + hklm_wow_key + '\\' + key, "value", hklm_wow_values[key]);
  }
}

hku_config = make_list();
foreach sid(keys(hku_values))
{
  if (max_index(keys(hku_values[sid])) > 0)
  {
    hku_key = 'HKU\\' + sid + '\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings\\';
    foreach key(keys(hku_values[sid]))
    {
      hku_config[max_index(hku_config)] = make_array("sid", sid, "key", hku_key + key, "value", hku_values[key]);
    }
  }
}

i = 0;
attachments = make_list();
if (max_index(hklm_config) > 0)
{
  header = header_from_list(list:make_list("key", "value"));
  csv = generate_csv(header:header, data:hklm_config);
  attachments[i] = make_array();
  attachments[i]["name"] = "system_wsh_config.csv";
  attachments[i]["value"] = csv;
  attachments[i]["type"] = "text/csv";
  ++i;
}

if (max_index(hklm_wow_config) > 0)
{
  header = header_from_list(list:make_list("key", "value"));
  csv = generate_csv(header:header, data:hklm_wow_config);
  attachments[i] = make_array();
  attachments[i]["name"] = "system_wow_wsh_config.csv";
  attachments[i]["value"] = csv;
  attachments[i]["type"] = "text/csv";
  ++i;
}

if (max_index(hku_config) > 0)
{
  header = header_from_list(list:make_list("sid", "key", "value"));
  csv = generate_csv(header:header, data:hku_config);
  attachments[i] = make_array();
  attachments[i]["name"] = "user_wsh_config.csv";
  attachments[i]["value"] = csv;
  attachments[i]["type"] = "text/csv";
  ++i;
}

if (max_index(attachments) > 0)
{
  report = 'Windows scripting host configuration attached.';
  security_report_with_attachments(port:0, level:0, extra:report, attachments:attachments);
}
else
{
  exit(0, "Windows scripting host configuration not found.");
}
