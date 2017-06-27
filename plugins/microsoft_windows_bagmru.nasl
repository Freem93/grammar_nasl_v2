#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92416);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/06 19:52:16 $");

  script_name(english:"BagMRU Folder History");
  script_summary(english:"BagMRU open folder history."); 

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate folders that were opened in Windows
Explorer.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to enumerate folders that were opened in Windows
Explorer. Microsoft Windows maintains folder settings using a registry
key known as shellbags or BagMRU. The generated folder list report
contains folders local to the system, folders from past mounted
network drives, and folders from mounted devices.");
  script_set_attribute(attribute:"see_also", value:"http://www.williballenthin.com/forensics/shellbags/");
  # https://digital-forensics.sans.org/blog/2008/10/31/shellbags-registry-forensics
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db25594f");
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

global_var bagmru_list, bagmru_list_cache;
bagmru_list = make_array();
bagmru_list_cache = make_array();

##
# HKEY_USERS\\<sid>\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU
# HKEY_USERS\\<sid>\\Software\\Microsoft\\Windows\\Shell\\BagMRU
# http://www.4n6k.com/2013/12/shellbags-forensics-addressing.html
# https://dl.4n6k.com/p/shellbags/shellbags.txt
# https://docs.google.com/a/tenable.com/file/d/0B-VYGsDJPtZlVDNJQ3pWX0M1b1k/edit
##
function get_bagMRU()
{
  local_var hku, hku_list, user, res, keys, key, i, bagmru, username;

  keys = make_list('\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU',
                   '\\Software\\Microsoft\\Windows\\Shell\\BagMRU');

  registry_init();
  hku = registry_hive_connect(hive:HKEY_USERS);
  if (isnull(hku))
  {
    close_registry();
    return NULL;
  }

  hku_list = get_registry_subkeys(handle:hku, key:'');
  foreach user (hku_list)
  {
    bagmru = make_array();
    username = get_hku_usernames(handle:hku, sid:user);

    foreach key (keys)
    {
      bagmru_recurse_dir(handle:hku, key:user+key);
    }

    if (max_index(keys(bagmru_list_cache)) > 0 )
    {
      if (!isnull(username))
      {
        bagmru_list[username] = bagmru_list_cache;
      }
      else
      {
        bagmru_list[user] = bagmru_list_cache;
      }
    }

    bagmru_list_cache = make_array();
  }

  RegCloseKey(handle:hku);
  close_registry();

  return 0;
}

##
# Private
##
function bagmru_recurse_dir(username, handle, key)
{
  local_var val, bk, bagmru_keys, bagmru_vals, bmruval, hexval, asciival, ret;
  
  bagmru_keys = get_registry_subkeys(handle:handle, key:key);
  bagmru_vals = get_reg_name_value_table(handle:handle, key:key);

  if (!isnull(bagmru_vals))
  {
    foreach bmruval (keys(bagmru_vals))
    {
      ret = get_raw_ascii_hex_values(val:bagmru_vals[bmruval]);
      bagmru_vals[bmruval] = ret;
      bagmru_list_cache['HKEY_USERS\\'+key] = bagmru_vals;
    }
  }

  if (!isnull(bagmru_keys))
  {
    foreach bk (bagmru_keys)
    {
      bagmru_recurse_dir(handle:handle, key:key+'\\'+bk);
      bagmru_vals = get_reg_name_value_table(handle:handle, key:key+'\\'+bk);
      foreach bmruval (keys(bagmru_vals))
      {
        ret = get_raw_ascii_hex_values(val:bagmru_vals[bmruval]);
        bagmru_vals[bmruval] = ret;
        bagmru_list_cache['HKEY_USERS\\'+key+'\\'+bk] = bagmru_vals;
      }
    }
  }

}

get_bagMRU();

bagmru_report = '';
foreach user (keys(bagmru_list))
{
  foreach regkey (keys(bagmru_list[user]))
  {
    foreach entry (keys(bagmru_list[user][regkey]))
    {
      user =   format_for_csv(data:user);
      regkey = format_for_csv(data:regkey);
      entry =  format_for_csv(data:entry);
      hex =    bagmru_list[user][regkey][entry]['hex'];
      raw =    format_for_csv(data:bagmru_list[user][regkey][entry]['raw']);
      ascii =  format_for_csv(data:bagmru_list[user][regkey][entry]['ascii']);

      bagmru_report += '"' + user + '","' + regkey + '","'+ entry + '","' + hex + '","' + ascii +  '","' + raw + '"\n';
    }
  }
}


if (strlen(bagmru_report) > 0)
{
  bagmru_report = 'user,regkey,entry,hex,ascii,raw\n'+bagmru_report;

  report = 'BagMRU report attached.\n';
  system = get_system_name();
  
  attachments = make_list();
  attachments[0] = make_array();
  attachments[0]["type"] = "text/csv";
  attachments[0]["name"] = "bagmru_"+system+".csv";
  attachments[0]["value"] = bagmru_report;
  security_report_with_attachments(
    port  : 0,
    level : 0,
    extra : report,
    attachments : attachments
  );
}
else
{
  exit(0, "No BagMRU information found.");
}
