# @DEPRECATED@
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(56124);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/02/10 15:03:52 $");

  script_name(english:"MS KB2616676: Fraudulent Digital Certificates Could Allow Spoofing (deprecated)");
  script_summary(english:"Checks for MS KB2616676");

  script_set_attribute(
    attribute:"synopsis",
    value:
"This plugin has been deprecated."
  );
  script_set_attribute(attribute:"description", value:
"Due to the issuance of several fraudulent SSL certificates, the root
certificates from the certificate authority DigiNotar have been placed
in the Microsoft Untrusted Certificate Store.");

  script_set_attribute(attribute:"solution", value:
"Microsoft has issued a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2.

http://support.microsoft.com/kb/2616676");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion", "SMB/ProductName");
  script_require_ports(139, 445);

  exit(0);
}

exit(0, "This plugin has been deprecated. Use smb_kb2982792.nasl (plugin ID 76464) instead.");

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');
winver = get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if ('Windows Embedded' >< get_kb_item_or_exit('SMB/ProductName'))
  exit(0, 'The host is running Windows Thin OS, and thus is not affected.');

if (hotfix_check_sp(xp:4, win2003:3, vista:3, win7:2) <= 0) exit(0, 'The host is not affected based on its version / service pack.');

if (!is_accessible_share()) exit(1, 'is_accessible_share() failed.');

if (hotfix_check_sp(xp:4, win2003:3) > 0)
{
  if (
    # Windows 2003 / XP 64-bit
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"crypt32.dll", version:"5.131.3790.4905", dir:'\\system32') ||

    # Windows XP 32-bit
    hotfix_is_vulnerable(os:"5.1", sp:3, file:"crypt32.dll", version:"5.131.2600.6149", dir:'\\system32')
  )
  {
    hotfix_security_warning();
    hotfix_check_fversion_end();
    exit(0);
  }
}
else
{
  hotfix_check_fversion_end();
  patchcerts = make_list(
      '637162CC59A3A1E25956FA5FA8F60D2E1C52EAC6',
      '7D7F4414CCEF168ADF6BF40753B5BECD78375931',
      '1916A2AF346D399F50313C393200F14140456616',
      '305F8BD17AA2CBC483A4C41B19A39A0C75DA39D6',
      '471C949A8143DB5AD5CDF1C972864A2504FA23C9',
      '61793FCBFA4F9008309BBA5FF12D2CB29CD4151A',
      '63FEAE960BAA91E343CE2BD8B71798C76BDB77D0',
      '6431723036FD26DEA502792FA595922493030F97',
      'CEA586B2CE593EC7D939898337C57814708AB2BE',
      '80962AE4D6C5B442894E95A13E4A699E07D694CF',
      'D018B62DC518907247DF50925BB09ACF4A5CB3AD',
      'C060ED44CBD881BD0EF86C0BA287DDCF8167478C',
      '43D9BCB568E039D073A74A71D8511F7476089CC3',
      '40AA38731BD189F9CDB5B9DC35E2136F38777AF4',
      '5DE83EE82AC5090AEA9D6AC4E7A6E213F946E179',
      'B533345D06F64516403C00DA03187D3BFEF59156',
      '2B84BFBB34EE2EF949FE1CBE30AA026416EB2216',
      '367D4B3B4FCBBC0B767B2EC0CDB2A36EAB71A4EB',
      '86E817C81A5CA672FE000F36F878C19518D6F844',
      '9845A431D51959CAF225322B4A4FE9F223CE6D15',
      'B86E791620F759F17B8D25E38CA8BE32E7D5EAC2',
      'F8A54E03AADC5692B850496A4C4630FFEAA29D83'
    );
  # Check the registry
  name   = kb_smb_name();
  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();
  port   = kb_smb_transport();

  if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:'IPC$');
  if (rc != 1)
  {
    NetUseDel();
    exit(1, 'Can\'t connect to IPC$ share.');
  }

  hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
  if (isnull(hklm))
  {
    NetUseDel();
    exit(1, 'Can\'t connect to remote registry.');
  }

  # check for KB2677070
  if (winver =~ '6.[0-2]')
  {
    key = "SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate";
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if(!isnull(key_h))
    {
      blob = RegQueryValue(handle:key_h, item:"DisallowedCertEncodedCtl");
      RegCloseKey(handle:key_h);
      if(!isnull(blob) && blob != '')
      {
        RegCloseKey(handle:hklm);
        NetUseDel();
        exit(0, "KB2677070 Automatic Updater of Revoked Certificates is Installed.");
      }
    }
  }

  disallowedcerts = make_array();
  key = 'SOFTWARE\\Microsoft\\SystemCertificates\\Disallowed\\Certificates';
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

  if (!isnull(key_h))
  {
    info = RegQueryInfoKey(handle:key_h);
    for (i=0; i<info[1]; ++i)
    {
      subkey = RegEnumKey(handle:key_h, index:i);
      if (!isnull(subkey))
      {
        disallowedcerts[subkey] = 1;
      }
    }
    RegCloseKey(handle:key_h);
  }
  RegCloseKey(handle:hklm);

  NetUseDel();

  missingcerts = make_list();

  for (i=0; i < max_index(patchcerts); i++)
  {
    cert = patchcerts[i];
    if (!disallowedcerts[cert])
    {
      missingcerts = make_list(missingcerts, cert);
    }
  }


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
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}
exit(0, 'The host is not affected.');
