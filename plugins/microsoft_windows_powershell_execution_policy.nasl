#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92367);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/06 19:52:16 $");

  script_name(english:"Microsoft Windows PowerShell Execution Policy");
  script_summary(english:"Report PowerShell's execution policy.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to collect and report the PowerShell execution policy
for the remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to collect and report the PowerShell execution policy
for the remote Windows host and generate a report as a CSV attachment.");
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
  script_require_keys("SMB/Registry/Enumerated", "SMB/ARCH");
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

get_kb_item_or_exit("SMB/Registry/Enumerated");

arch = get_kb_item_or_exit('SMB/ARCH');

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

if (isnull(hklm))
{
   close_registry();
   audit(AUDIT_REG_FAIL);
}

installed = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\PowerShell\1\Install");
if (installed == 1)
{
  exec_policy_data = make_list();

  exec_policy_path = "SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell\ExecutionPolicy";
  exec_policy = get_registry_value(handle:hklm, item:exec_policy_path);

  if (isnull(exec_policy))
  {
    # Defaults to Restricted.
    exec_policy = "Restricted";
  }

  exec_policy_data[max_index(exec_policy_data)] = make_array("key", 'HKLM\\' + exec_policy_path, "value", exec_policy);
}

if (arch == "x64")
{
  installed = get_registry_value(handle:hklm, item:"SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\Install");
  if (installed == 1)
  {
    exec_policy_path = "SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell\ExecutionPolicy";
    exec_policy = get_registry_value(handle:hklm, item:exec_policy_path);
    if (isnull(exec_policy))
    {
      # Defaults to Restricted.
      exec_policy = "Restricted";
    }

    exec_policy_data[max_index(exec_policy_data)] = make_array("key", 'HKLM\\' + exec_policy_path, "value", exec_policy);
  }
}

RegCloseKey(handle:hklm);

close_registry();

if (max_index(exec_policy_data) > 0)
{
  exec_policy_data_header = header_from_list(list:make_list("key", "value"));
  csv = generate_csv(header:exec_policy_data_header, data:exec_policy_data);

  attachments = make_list();
  attachments[0] = make_array();
  attachments[0]["name"] = "powershell_execution_policy.csv";
  attachments[0]["value"] = csv;
  attachments[0]["type"] = "text/csv";

  report = 'PowerShell execution policy information attached.';
  security_report_with_attachments(port:0, level:0, extra:report, attachments:attachments);
}
else
{
  exit(0, "PowerShell not found on system.");
}
