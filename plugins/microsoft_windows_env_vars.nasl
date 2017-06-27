#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92364);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/06 19:52:16 $");

  script_name(english:"Microsoft Windows Environment Variables");
  script_summary(english:"Report environment variables.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to collect and report environment variables from the
remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to collect system and active account environment
variables on the remote Windows host and generate a report as a CSV
attachment.");
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

#HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
hklm_values = get_reg_name_value_table(handle:hklm, key:"SYSTEM\CurrentControlSet\Control\Session Manager\Environment");

RegCloseKey(handle:hklm);

#HKU\<SID>\Environment
hku_values = get_hku_key_values(key:"\Environment", reg_init:FALSE, resolve_sid:FALSE);
if (isnull(hku_values))
{
   close_registry();
   audit(AUDIT_REG_FAIL);
}

close_registry();

hklm_env = make_list();
foreach key(keys(hklm_values))
{
   hklm_env[max_index(hklm_env)] = make_array("name", key, "value", hklm_values[key]);
}

hku_env = make_list();
foreach sid(keys(hku_values))
{
   foreach key(keys(hku_values[sid]))
   {
      hku_env[max_index(hku_env)] = make_array("sid", sid, "name", key, "value", hku_values[sid][key]);
   }
}

attachments = make_list();
i = 0;
if (max_index(hklm_env) > 0)
{
  header = header_from_list(list:make_list("name", "value"));
  csv = generate_csv(header:header, data:hklm_env);
  attachments[i] = make_array();
  attachments[i]["name"] = "system_environment_variables.csv";
  attachments[i]["value"] = csv;
  attachments[i]["type"] = "text/csv";
  ++i;
}

if (max_index(hku_env) > 0)
{
  header = header_from_list(list:make_list("sid", "name", "value"));
  csv = generate_csv(header:header, data:hku_env);
  attachments[i] = make_array();
  attachments[i]["name"] = "user_environment_variables.csv";
  attachments[i]["value"] = csv;
  attachments[i]["type"] = "text/csv";
  ++i;
}

if (max_index(attachments) > 0)
{
  report = 'Environment variable information attached.';
  security_report_with_attachments(port:0, level:0, extra:report, attachments:attachments);
}
else
{
  exit(0, "Environment variable information not found.");
}
