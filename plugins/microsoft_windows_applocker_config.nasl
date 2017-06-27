#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92362);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/06 19:52:16 $");

  script_name(english:"Microsoft Windows AppLocker Configuration");
  script_summary(english:"Report Applocker's configuration.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to collect and report AppLocker's configuration on the
remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to collect AppLocker configuration information on the
remote Windows host and generate a report as a CSV attachment.");
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

function enum_applocker_registry(key, hklm, wow)
{
  local_var close_hklm, values, index, subkeys, subkey, ret;

  if (isnull(key))
  {
    if (wow)
    {
      key = "SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\SrpV2";
    }
    else
    {
      key = "SOFTWARE\Policies\Microsoft\Windows\SrpV2";
    }
  }

  if (isnull(hklm))
  {
    hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

    if (isnull(hklm))
    {
      close_registry();
      audit(AUDIT_REG_FAIL);
    }
    close_hklm = TRUE;
  }
  else
  {
    close_hklm = FALSE;
  }

  values = get_reg_name_value_table(handle:hklm, key:key);
  subkeys = get_registry_subkeys(handle:hklm, key:key);
  ret = make_list();
  if (max_index(keys(values)) > 0)
  {
    foreach index(keys(values))
    {
      ret[max_index(ret)] = make_array("key", 'HKLM\\' + key + '\\' + index, "value", values[index]);
    }
  }

  foreach subkey(subkeys)
  {
    ret = make_list(ret, enum_applocker_registry(key:key + '\\' + subkey, hklm:hklm));
  }

  if (close_hklm)
  {
    RegCloseKey(handle:hklm);
  }

  return ret;
}

get_kb_item_or_exit("SMB/Registry/Enumerated");

arch = get_kb_item_or_exit('SMB/ARCH');

registry_init();

applocker_config = enum_applocker_registry();

if (arch == "x64")
{
  applocker_config = make_list(applocker_config, enum_applocker_registry(wow:TRUE));
}

close_registry();

if (max_index(applocker_config) == 0)
{
  exit(0, "No AppLocker configuration found.");
}
else
{
  applocker_config_header = header_from_list(list:make_list("key", "value"));
  csv = generate_csv(header:applocker_config_header, data:applocker_config);
  attachments = make_list();
  attachments[0] = make_array();
  attachments[0]["name"] = "applocker_config.csv";
  attachments[0]["value"]= csv;
  attachments[0]["type"] = "text/csv";

  report = 'AppLocker configuration attached.';
  security_report_with_attachments(port:0, level:0, extra:report, attachments:attachments);
}
