#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92415);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/06 19:52:16 $");

  script_name(english:"Application Compatibility Cache");
  script_summary(english:"Report application compatibility settings.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to gather application compatibility settings on the
remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to generate a report on the application compatibility
cache on the remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"https://dl.mandiant.com/EE/library/Whitepaper_ShimCacheParser.pdf");
  # https://digital-forensics.sans.org/summit-archives/DFIR_Summit/Johnny-AppCompatCache-the-Ring-of-Malware-Brice-Daniels-and-Mary-Singh.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a076105");

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

  script_dependencies("smb_hotfixes.nasl", "smb_reg_service_pack.nasl", "set_kb_system_name.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("charset_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

exit(0, "This plugin is temporarily disabled");

##
# HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache
##
function get_ApplicationCompatibilityCache()
{
  local_var hklm, res, ret, key, entries;

  key = 'SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache';
  ret = make_array();
 
  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE);
  if (isnull(hklm))
  {
    close_registry();
    return NULL;
  }

  ret = get_reg_name_value_table(handle:hklm ,key:key);

  RegCloseKey(handle:hklm);
  close_registry();

  return ret;
}

value = get_ApplicationCompatibilityCache();

att_report = '';
foreach val (keys(value))
{
  rah_vals = get_raw_ascii_hex_values(val:value[val]);
  if (isnull(rah_vals)) continue;

  att_report +=  val +','+rah_vals['hex']+'\n';
}


if (strlen(att_report) > 0)
{
  att_report = 'key,value\n' + att_report;

  report = 'Application compatibility cache report attached.\n';
  system = get_system_name();
  
  attachments = make_list();
  attachments[0] = make_array();
  attachments[0]["type"] = "text/csv";
  attachments[0]["name"] = "application_combatibility_cache_"+system+".csv";
  attachments[0]["value"] = att_report;
  security_report_with_attachments(
    port  : 0,
    level : 0,
    extra : report,
    attachments : attachments
  );
}
else
{
  exit(0, "No Appcompat data found.");
}
