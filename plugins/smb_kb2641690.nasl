# @DEPRECATED@
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56955);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/10 15:03:52 $");

  script_name(english:"MS KB2641690: Fraudulent Digital Certificates Could Allow Spoofing (deprecated)");
  script_summary(english:"Checks for MS KB2641690");

  script_set_attribute(
    attribute:"synopsis",
    value:
"This plugin has been deprecated."
  );
  script_set_attribute(attribute:"description", value:
"Due to the issuance of several fraudulent SSL certificates, two
DigiCert Sdn. Bhd. intermediate certificates have been placed in the
Microsoft Untrusted Certificate Store.");
 
  script_set_attribute(attribute:"solution", value:
"Microsoft has issued a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2 :

http://support.microsoft.com/kb/2641690");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/28");
  
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_disallowed_certs.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion", "SMB/ProductName");
  script_require_ports(139, 445);

  exit(0);
}

exit(0, "This plugin has been deprecated. Use smb_kb2982792.nasl (plugin ID 76464) instead.");

include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');
winver = get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp(xp:4, win2003:3, vista:3, win7:2) <= 0) exit(0, 'The host is not affected based on its version / service pack.');

if ('Windows Embedded' >< get_kb_item_or_exit('SMB/ProductName'))
  exit(0, 'The host is running Windows Thin OS, and thus is not affected.');

# check for KB2677070
if (winver =~ '6.[0-2]')
{
  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  key = "SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate\DisallowedCertEncodedCtl";
  data = get_registry_value(handle:hklm, item:key);
  RegCloseKey(handle:hklm);
  close_registry();

  if(!isnull(data) && data != '')
    exit(0, "KB2677070 Automatic Updater of Revoked Certificates is Installed.");
}

if (!is_accessible_share()) exit(1, 'is_accessible_share() failed.');

if (hotfix_check_sp(xp:4, win2003:3) > 0)
{
  if (
    # Windows 2003 / XP 64-bit
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"crypt32.dll", version:"5.131.3790.4933", dir:'\\system32') ||
  
    # Windows XP 32-bit
    hotfix_is_vulnerable(os:"5.1", sp:3, file:"crypt32.dll", version:"5.131.2600.6154", dir:'\\system32')
  )
  {
    hotfix_security_warning();
    hotfix_check_fversion_end();
    exit(0);
  }
}
else
{
  patchcerts = make_list(
    '51C3247D60F356C7CA3BAF4C3F429DAC93EE7B74',
    '8E5BD50D6AE686D65252F843A9D4B96D197730AB'
  );

  # Get a list of disallowed certs, then put the values in a
  # hash so its easier to search
  missingcerts = make_list();
  disallowedlist = get_kb_list('SMB/DisallowedCerts');
  if (!isnull(disallowedlist)) disallowedlist = list_uniq(make_list(disallowedlist));
  if (!isnull(disallowedlist))
  {
    disallowedarray = make_array();
    for (i=0; i < max_index(disallowedlist); i++)
    {
      cert = disallowedlist[i];
      disallowedarray[cert] = 1;
    }
 
    for (i=0; i < max_index(patchcerts); i++)
    {
      cert = patchcerts[i];
      if (!disallowedarray[cert])
      {
        missingcerts = make_list(missingcerts, cert);
      }
    }
  }
  else missingcerts = patchcerts;

  if (max_index(missingcerts) > 0)
  {
    if (report_verbosity > 0)
    {
      if (max_index(missingcerts) > 1) s = 's are missing';
      else s = ' is missing';

      report = '\nThe following certificate'+s+' from the disallowed certificate registry :\n';
      for (i=0; i < max_index(missingcerts); i++)
      {
        report += '\n' + missingcerts[i];
      }
      security_warning(port:get_kb_item('SMB/transport'), extra:report);
    }
    else security_warning(get_kb_item('SMB/transport'));
    exit(0);
  }
}

exit(0, 'The host is not affected.');
