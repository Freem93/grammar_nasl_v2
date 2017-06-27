#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59785);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/11 19:58:27 $");

  script_bugtraq_id(54138);
  script_osvdb_id(83092, 83093, 83094, 83095);
  script_xref(name:"EDB-ID", value:"19331");
  script_xref(name:"EDB-ID", value:"19332");
  script_xref(name:"EDB-ID", value:"19333");
  script_xref(name:"EDB-ID", value:"19334");
  
  script_name(english:"ACDSee Pro < 5.2 Multiple Memory Corruption Vulnerabilities");
  script_summary(english:"Checks version of ACDSee Pro");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an image editing application installed 
that is affected by multiple code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"ACDSee, an image editing application, is installed on the remote 
host.  The installed version of ACDSee is earlier than 5.2 and thus
is potentially affected by multiple vulnerabilities :

  - Insufficient validation in ID_ICO.apl when copying 
    colors from cursors in .CUR files can be exploited to
    cause a heap-based buffer overflow.

  - An error in IDE_ACDStd.apl when allocating memory based
    on values in the Logical Screen Descriptor of a GIF 
    image can be exploited to corrupt heap memory.

  - Insufficient validation of ID_PICT.apl of specific byte
    values used as sizes in the image content can be 
    exploited to cause a heap-based buffer overflow.

  - Insufficient validation in IDE_ACDStd.apl of specific 
    byte values used as sizes in the image content when 
    decompressing run-length encoded bitmaps can be 
    exploited to cause a heap-based buffer overflow.");

  script_set_attribute(attribute:"solution", value:"Upgrade to ACDSee version 5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?19c5feb3");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7eec010e");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6335c667");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6fc57f31");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:acdsystems:acdsee");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("audit.inc");

app = 'ACDSee Pro';

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\ACD Systems\ACDSee Pro";
subkeys = get_registry_subkeys(handle:hklm, key:key);
paths = make_array();

foreach subkey (subkeys)
{
  if (subkey =~ '^[0-9]+$')
  {
    entry = key + '\\' + subkey + "\InstallDir";
    path = get_registry_value(handle:hklm, item:entry);

    if (!isnull(path))
    {
      item = eregmatch(pattern:'(^[0-9])*', string:subkey);
      if (!isnull(item))
      {
        major = item[1];
        paths[major] = path;
      }
    }
  }
}

RegCloseKey(handle:hklm);

if (max_index(keys(paths)) == 0)
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}
close_registry(close:FALSE);

validatedinstall = FALSE;
vuln = 0;
info = '';
info2 = '';
foreach majver (keys(paths))
{
  exe = paths[majver] + "\ACDSeePro"+majver+".exe";
  ver = hotfix_get_fversion(path:exe);
  if (!isnull(ver['value']))
  {
    validatedinstall = TRUE;
    version = join(sep:'.', ver['value']);
    if (ver_compare(ver:version, fix:'5.2.157.0') == -1)
    {
      vuln++;
      info += 
        '\n  Path              : ' + paths[majver] +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 5.2.157.0\n';
    }
    else info2 += ' and ' + version;
  }
}

hotfix_check_fversion_end();
if (!validatedinstall)
  audit(AUDIT_UNINST, app);

if (info)
{
  if (report_verbosity > 0) security_hole(port:get_kb_item('SMB/transport'), extra:info);
  else security_hole(get_kb_item('SMB/transport'));
  exit(0);
}

if (info2)
{
  info2 -= ' and ';
  if (' and ' >< info2) be = 'are';
  else be = 'is';

  exit(0, 'The host is not affected since ACDSee Pro ' + info2 + ' ' + be + ' installed.');
}
else exit(1, 'Unexpected error - \'info2\' is empty.');
