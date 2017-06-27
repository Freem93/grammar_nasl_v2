#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(69477);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/03 17:40:02 $");

  script_cve_id("CVE-2013-1087");
  script_bugtraq_id(61188);
  script_osvdb_id(95377);

  script_name(english:"Novell GroupWise Client 8.x < 8.0.3 Hot Patch 3 / 2012.x < 2012 SP2 XSS");
  script_summary(english:"Checks version of grpwise.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an email application that is affected
by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Novell GroupWise Client installed on the remote 
Windows host is 8.x prior to 8.0.3 Hot Patch 3 (8.0.3.28711) or 2012.x 
prior to 2012 SP2 (12.0.2.18211).  It is, therefore, reportedly 
affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://www.novell.com/support/kb/doc.php?id=7012063");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Novell GroupWise Client 8.0.3 Hot Patch 3 (8.0.3.28711) /
2012 SP2 (12.0.2.18211) or later.  Additionally, apply the required  
registry changes from the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:groupwise");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("groupwise_client_installed.nasl");
  script_require_keys("SMB/Novell GroupWise Client/Path", "SMB/Novell GroupWise Client/Version");
  script_require_ports(139, 445);

  exit(0);
}

include('audit.inc');
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include('misc_func.inc');

version = get_kb_item_or_exit('SMB/Novell GroupWise Client/Version');
path = get_kb_item_or_exit('SMB/Novell GroupWise Client/Path');

if (version =~ '^8\\.' && ver_compare(ver:version, fix:'8.0.3.28711') == -1)
  fixed_version = '8.0.3 Hot Patch 3 (8.0.3.28711)';
else if (version =~ '^12\\.' && ver_compare(ver:version, fix:'12.0.2.18211') == -1)
  fixed_version = '2012 SP2 (12.0.2.18211)';

info = '';
if (fixed_version)
{
  port = kb_smb_transport();

  set_kb_item(name:'www/0/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else
{
  info = '';
  port = kb_smb_transport();
  registry_init();

  # Make sure the registry is configured correctly
  hku = registry_hive_connect(hive:HKEY_USERS);
  if (isnull(hku))
  {
    close_registry();
    audit(AUDIT_REG_FAIL);
  }

  key_h = RegOpenKey(handle:hku, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    reginfo = RegQueryInfoKey(handle:key_h);
    if (!isnull(reginfo));
    {
      for (i=0; i < reginfo[1]; i++)
      {
        subkey = RegEnumKey(handle:key_h, index:i);
        if (subkey =~ '^S-1-5-21-[0-9\\-]+$')
        {
          # First check if the Novell\Groupwise\Client hive exists under the user key
          # If not, this implies that they have never used the application
          key = subkey + '\\Software\\Novell\\GroupWise\\Client\\';
          res = get_registry_subkeys(handle:hku, key:key);
          if (isnull(res))
            continue;

          key = subkey + "\Software\Novell\GroupWise\Client\Setup\HTMLScriptsBlocked";
          res = get_registry_value(handle:hku, item:key);
          if (isnull(res) || res == 0)
            info += '  ' + subkey + '\n';
        }
      }
    }
    RegCloseKey(handle:key_h);
  }
  RegCloseKey(handle:hku);
  NetUseDel();

  if (info) 
  {
    set_kb_item(name:'www/0/XSS', value:TRUE);
    if (report_verbosity > 0)
    {
      info = 
        '\nThe ability to run scripts has not been disabled for the following' +
        '\nSIDs :' +
        '\n' +
        info + 
        '\nNote that this check may be incomplete as Nessus can only check the' +
        '\nSIDs of logged on users.\n';
      security_warning(port:port, extra:info);
    }
    else security_warning(port);
    exit(0);
  }
  else 
  {
    extra =
      'The ability to run scripts has been disabled for all detected users.\n' +
      'Note that the check may not be complete, as Nessus can only check the\n' +
      'SIDs of logged on users.\n';
    exit(0, extra);
  }
}
