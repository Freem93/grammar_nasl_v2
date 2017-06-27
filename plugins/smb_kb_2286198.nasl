#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(47750);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2017/04/19 13:27:09 $");

  script_cve_id("CVE-2010-2568");
  script_bugtraq_id(41732);
  script_osvdb_id(66387);
  script_xref(name:"CERT", value:"940193");
  script_xref(name:"EDB-ID", value:"14403");
  script_xref(name:"MSFT", value:"MS10-046");
  script_xref(name:"Secunia", value:"40647");

  script_name(english:"MS KB2286198: Windows Shell Shortcut Icon Parsing Arbitrary Code Execution (EASYHOOKUP)");
  script_summary(english:"Checks if displaying shortcut icons has been disabled");

  script_set_attribute(attribute:"synopsis", value:
"It may be possible to execute arbitrary code on the remote Windows
host using a malicious shortcut file.");
  script_set_attribute(attribute:"description", value:
"Windows Shell does not properly validate the parameters of a shortcut
file when loading its icon. Attempting to parse the icon of a
specially crafted shortcut file can result in arbitrary code
execution. A remote attacker could exploit this by tricking a user
into viewing a malicious shortcut file via Windows Explorer, or any
other application that parses the shortcut's icon. This can also be
exploited by an attacker who tricks a user into inserting removable
media containing a malicious shortcut (e.g. CD, USB drive), and
AutoPlay is enabled.

EASYHOOKUP is one of multiple Equation Group vulnerabilities and
exploits disclosed on 2017/04/14 by a group known as the Shadow
Brokers.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2286198");
  script_set_attribute(
    attribute:"see_also",
    value:"http://technet.microsoft.com/en-us/security/bulletin/MS10-046"
  );
  script_set_attribute(attribute:"solution", value:
"Either apply the MS10-046 patch or disable the displaying of shortcut
icons (refer to the Microsoft advisory).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows Shell LNK Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_nt_ms10-046.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("audit.inc");


get_kb_item_or_exit('SMB/WindowsVersion');
if (hotfix_check_sp(xp:4, win2003:3, vista:3, win7:1) <= 0)
  exit(0, 'Host is not affected based on its version / service pack.');
if (!get_kb_item("SMB/Missing/MS10-046")) exit(0, "The host is not affected because the 'SMB/Missing/MS10-046' KB item is missing.");

# Connect to the appropriate share.
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();
port    =  kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

hkcr = RegConnectRegistry(hkey:HKEY_CLASS_ROOT);
if (isnull(hkcr))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}

keys = make_list(
  'lnkfile\\shellex\\IconHandler',
  'piffile\\shellex\\IconHandler'
);

vuln = make_array();

foreach key (keys)
{
  key_h = RegOpenKey(handle:hkcr, key:key, mode:MAXIMUM_ALLOWED);
  icon_handler = NULL;

  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value[1])) vuln[key] = value[1];
    RegCloseKey(handle:key_h);
  }
}

RegCloseKey(handle:hkcr);
NetUseDel();

if (max_index(keys(vuln)) > 0)
{
  if (report_verbosity > 0)
  {
    if (max_index(keys(vuln)) > 1) s = 'ies';
    else s = 'y';
    report =
      '\nAccording to the following registry entr'+s+', displaying shortcut' +
      '\nicons has not been disabled :\n';

    foreach key (keys(vuln))
    {
      report +=
        '\n  Key   : HKEY_CLASS_ROOT\\' + key +
        '\n  Value : ' + vuln[key] + '\n';
    }

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, 'Displaying shortcut icons has been disabled.');

