#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# smb_hotfixes.inc
# $Revision: 1.68 $

include("global_settings.inc");

global_var OFFICE_MAJOR_VERS;
OFFICE_MAJOR_VERS = make_list("8.0", "9.0", "10.0", "11.0", "12.0", "14.0", "15.0", "16.0");

# nb: this is used internally by 'hotfix_check_3rd_party()'.
_pmtool_names = make_array(
  'shavlik', 'VMware Go',
  'sccm', 'SCCM',
  'wsus', 'WSUS',
  'ibm_tem', 'IBM TEM',
  'k1000', 'Dell KACE K1000',
  'altiris', 'Symantec Altiris'
);

function hotfix_check_exchange_installed()
{
 local_var vers;

 vers = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Exchange/Setup/ServicePackBuild");
 if ( ! vers )
	return NULL;
 else
	return vers;
}

function hotfix_data_access_version()
{
 local_var vers;

 vers = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/DataAccess/Version");
 if ( ! vers )
	return NULL;
 else
	return vers;
}

##
# Determine the Office versions that are installed
#
# @return an array of office versions
function hotfix_check_office_version()
{
  local_var ret, ver;
  local_var kbs;

  ret = make_array();

  foreach ver (OFFICE_MAJOR_VERS)
  {
    if (!isnull(get_kb_list("SMB/Office/*/"+ver+"/Path")))
    {
      ret[ver] = 1;
    }
  }

  if (max_index(keys(ret)) > 0) return ret;
  return NULL;
}

#
# Returns Word version if it is installed, NULL if it is not
#
function hotfix_check_word_version()
{
 local_var flag;

 flag = get_kb_item("SMB/Office/Word");
 if ( flag )
   return flag;

 return NULL;
}

#
# Returns Excel version if it is installed, NULL if it is not
#
function hotfix_check_excel_version()
{
 local_var flag;

 flag = get_kb_item("SMB/Office/Excel");
 if ( flag )
   return flag;

 return NULL;
}

#
# Returns Powerpoint version if it is installed, NULL if it is not
#
function hotfix_check_powerpoint_version()
{
 local_var flag;

 flag = get_kb_item("SMB/Office/Powerpoint");
 if ( flag )
   return flag;

 return NULL;
}

#
# Returns Publisher version if it is installed, NULL if it is not
#
function hotfix_check_publisher_version()
{
 local_var flag;

 flag = get_kb_item("SMB/Office/Publisher");
 if ( flag )
   return flag;

 return NULL;
}

#
# Returns Outlook version if it is installed, NULL if it is not
#
function hotfix_check_outlook_version()
{
 local_var list;

 list = get_kb_list("SMB/Office/Outlook/*/Path");
 if (list) return list;

 return NULL;
}

function hotfix_check_ie_version()
{
 local_var flag;

 flag = get_kb_item("SMB/IE/Version");
 if ( flag )
   return flag;

 return NULL;
}

function hotfix_ie_gt()
{
 local_var vers;

 vers = hotfix_check_ie_version();
 if ( vers == NULL ) return -1;

 if ( ereg(pattern:strcat("^", _FCT_ANON_ARGS[0]), string:vers) )
	return 1;
 else
	return 0;
}

#
# Returns 1 if Works is installed, 0 if it is not
#
function hotfix_check_works_installed()
{
 local_var flag;

 flag = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Works");
 if ( ! flag )
	return 0;
 else
	return 1;
}

#
# Returns 1 if IIS is installed, 0 if it is not and -1 if we don't know
#
function hotfix_check_iis_installed()
{
 local_var w3svc;

 w3svc = get_kb_item("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/W3SVC/ImagePath");
 if ( ! w3svc ) return -1;
 if ( "inetinfo" >!< w3svc && "iis" >!< w3svc )
	return 0;
 else
	return 1;
}

#
# Returns 1 if WINS is installed, 0 if it is not and -1 if we don't know
#
function hotfix_check_wins_installed()
{
 local_var wins;

 wins = get_kb_item("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/WINS/DisplayName");
 if ( ! wins ) return -1;
 else
	return 1;
}

# Returns 1 if a DHCP server is installed, 0 if it is not and -1 if we don't know
#
function hotfix_check_dhcpserver_installed()
{

 local_var dhcp;
 dhcp = get_kb_item("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/DHCPServer");
 if ( ! dhcp ) return -1;
 else
	return 1;
}

function hotfix_check_nt_server()
{
 local_var product_options;
 product_options = get_kb_item("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Control/ProductOptions");
 if ( ! product_options ) return -1;
 if ("WinNT" >< product_options )
	return 0;
 else
	return 1;
}

function hotfix_check_domain_controler()
{
 local_var product_options;
 product_options = get_kb_item("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Control/ProductOptions");
 if ( ! product_options ) return -1;
 if ("LanmanNT" >< product_options )
	return 1;
 else
	return 0;
}

#-----------------------------------------------------------------------------
# hotfix_check_server_core()
#
# Returns:
# -1 : could not determine whether it's Server Core.
#  0 : it's not Server Core.
#  1 : it is Server Core.
#-----------------------------------------------------------------------------
function hotfix_check_server_core()
{
 local_var pname, ie, shell, version, servercore;

 # Server Core is only an option for Windows 2008 / 2008 R2 / 2012 / 2012 R2
 version = get_kb_item("SMB/WindowsVersion");

 if (!version) return -1;
 if ("6.0" >!< version && "6.1" >!< version && "6.2" >!< version && "6.3" >!< version && "10" >!< version) return 0;
 # Server Core doesn't have IE.
 ie = get_kb_item("SMB/IE/Version");
 if (!isnull(ie)) return 0;

 # Hyper-V Servers are also Server Core like servers
 pname = get_kb_item("SMB/ProductName");
 if ('Hyper-V Server' >< pname) return 1;

 # Windows 2008 / 2008 R2 Server Core doesn't have Windows Shell.
 #
 # nb: the following is the default shell in Server Core, although some
 #     people may tweak the setting, removing
 #     "runonce.exe /AlternateShellStartup".
 #
 #  cmd.exe /c "cd /d "%USERPROFILE%" & start cmd.exe /k runonce.exe /AlternateShellStartup"
 if ("6.0" >< version || "6.1" >< version)
 {
  shell = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Winlogon/Shell");
  if (!shell) return -1;

  if ("explorer.exe" >< tolower(shell)) return 0;
  if ("cmd.exe /c" >< shell && "start cmd.exe" >< shell)
   return 1;
  else
   return 0;
 }

 # Windows 2012 / 2012 R2 / 2016 / 2016 R2 Server Core
 if ("6.2" >< version || "6.3" >< version || "10" >< version)
 {
  servercore = get_kb_item("SMB/ServerCore");

  if (servercore)
   return 1;
  if (isnull(servercore))
   return -1;
  if (!servercore)
   return 0;
 }
}

function hotfix_get_mssqldir()
{
 return get_kb_item("MSSQL/Path");
}

function hotfix_get_programfilesdir()
{
 local_var str;
 str = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/ProgramFilesDir");
 return str;
}

function hotfix_get_programfilesdirx86()
{
 local_var str;
 str = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/ProgramFilesDirx86");
 return str;
}

function hotfix_get_commonfilesdir()
{
 local_var str;
 str = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/CommonFilesDir");
 return str;
}

function hotfix_get_commonfilesdirx86()
{
 local_var str;
 str = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/CommonFilesDirx86");
 return str;
}

##
# Determines the Office directory
#
# @param officever The Office version to check
#
# @return A string containing the path to a particular Office install or
#         an array of Office versions and their paths or
#         the root programfiles directory
##
function hotfix_get_officeprogramfilesdir(officever)
{
  local_var str, office_products, product, ver, ret;

  office_products = make_list("Outlook", "Word", "WordViewer", "Excel", "ExcelViewer", "Powerpoint", "Publisher");
  if (!isnull(officever))
  {
    foreach product (office_products)
    {
      str = get_kb_item("SMB/Office/"+product+"/"+officever+"/Path");
      if (str)
      {
        if ("Microsoft Office" >< str)
        {
          str = ereg_replace(pattern:"^([A-Za-z]:.*)\\Microsoft Office.*", replace:"\1", string:str);
          return str;
        }
      }
    }
  }
  else
  {
    foreach ver (OFFICE_MAJOR_VERS)
    {
      foreach product (office_products)
      {
        str = get_kb_item("SMB/Office/"+product+"/"+ver+"/Path");
        if (str)
        {
          if ("Microsoft Office" >< str)
          {
            str = ereg_replace(pattern:"^([A-Za-z]:.*)\\Microsoft Office.*", replace:"\1", string:str);
            ret[ver] = str;
            break;
          }
        }
      }
    }
    if (max_index(keys(ret)) > 0) return ret;
  }
  return hotfix_get_programfilesdir();
}

##
#
# @param officever The office version to check
#
# @return A string containing the path to a particular Office install or
#         an array of Office versions and their paths or
#         A string containing the root Common Files dir
##
function hotfix_get_officecommonfilesdir(officever)
{
 local_var bitness, str, office_products, product, ver, ret;

 office_products = make_list("Outlook", "Word", "WordViewer", "Excel", "ExcelViewer", "Powerpoint", "Publisher");
 if (!isnull(officever))
 {
   foreach product (office_products)
   {
     str = get_kb_item("SMB/Office/"+product+"/"+officever+"/Path");
     if (str)
     {
       if ("Microsoft Office" >< str && officever != "16.0")
       {
         str = ereg_replace(pattern:"^([A-Za-z]:.*)\\Microsoft Office.*", replace:"\1\Common Files", string:str);
         return str;
       }
       if ("Microsoft Office" >< str && officever == "16.0")
       {
         bitness = get_kb_item("SMB/Office/16.0/Bitness");
         if (! bitness)
           str = NULL;
         else
         {
           str = ereg_replace(pattern: "^([A-Za-z]:.*Microsoft Office).*",
                              replace: "\1\root\VFS\ProgramFilesCommon" + bitness,
                              string: str);
         }
         return str;
       }
     }
   }
 }
 else
 {
   foreach ver (OFFICE_MAJOR_VERS)
   {
     foreach product (office_products)
     {
       str = get_kb_item("SMB/Office/"+product+"/"+ver+"/Path");
       if (str)
       {
         if ("Microsoft Office" >< str)
         {
           str = ereg_replace(pattern:"^([A-Za-z]:.*)\\Microsoft Office.*", replace:"\1\Common Files", string:str);
           ret[ver] = str;
           break;
         }
       }
     }
   }
   if (max_index(keys(ret)) > 0) return ret;
 }

 return hotfix_get_commonfilesdir();
}

function hotfix_get_systemroot()
{
 local_var str;
 str = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/SystemRoot");
 return str;
}

##
# Returns the system drive letter.
#
# @param as_share returns the drive letter as an SMB share.
# @param as_dir returns the drive letter as a directory.
# @param exit_on_fail if TRUE, exits if unable to get system drive.
# @remark Just a wrapper around hotfix_get_systemroot() that parses
# out the drive path.
# @remark as_share and as_dir are mutually exclusive.
function hotfix_get_systemdrive(as_share, as_dir, exit_on_fail)
{
  local_var str, match;

  if (isnull(as_share)) as_share = FALSE;
  if (isnull(as_dir)) as_dir = FALSE;
  if (isnull(exit_on_fail)) exit_on_fail = FALSE;

  if (as_share && as_dir)
  {
    err_print('hotfix_get_systemdrive(): "as_dir" and "as_share" are mutually exclusive.');
    if (exit_on_fail) exit(1, "Bad arguments passed to hotfix_get_systemdrive().");
    return NULL;
  }

  str = hotfix_get_systemroot();
  if (isnull(str))
  {
    if (exit_on_fail) exit(1, "Failed to get system root.");
    return NULL;
  }
  match = eregmatch(string:str, pattern:"^(([A-Za-z]):\\)");
  if (isnull(match))
  {
    if (exit_on_fail) exit(1, "Failed to parse system root.");
    return NULL;
  }
  if (as_share) return strcat(match[2],'$');
  else if (as_dir) return match[1];
  else return match[2];
}

##
# Returns the programdata directory.
#
# @remark Just a wrapper around hotfix_get_systemdrive() that parses
# out the drive path after checking for the existence of ProgramData
# on the target and then appends the ProgramData path to the path.
function hotfix_get_programdata(exit_on_fail)
{
  local_var str, match, key;
  key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion/ProfileList/ProgramData";

  local_var programdata_exists = get_kb_item(key);

  if (isnull(exit_on_fail)) exit_on_fail = FALSE;

  if("%SystemDrive%\ProgramData" >< programdata_exists)
    programdata_exists = TRUE;
  else
    programdata_exists = FALSE;

  if (programdata_exists)
  {
    str = hotfix_get_systemdrive(as_dir:TRUE, exit_on_fail:TRUE);
    if (isnull(str))
    {
      if (exit_on_fail) exit(1, "Failed to get system root.");
      return NULL;
    }
    match = eregmatch(string:str, pattern:"^(([A-Za-z]):\\)");
    if (isnull(match))
    {
      if (exit_on_fail) exit(1, "Failed to parse system root.");
      return NULL;
    }
    match[1] += "ProgramData";

    return match[1];
  }
}

function hotfix_check_sp(nt, win2k, xp, win2003, vista, win7, win8, win81)
{
  local_var vers, sp;

  vers = get_kb_item("SMB/WindowsVersion");
  if ( ! vers ) return -1;

  if ( nt &&  "4.0" >< vers )
  {
    sp  = get_kb_item("SMB/CSDVersion");
    if ( sp )
    	sp   = int(ereg_replace(string:sp, pattern:".*Service Pack ([0-9]).*", replace:"\1"));
    else
	sp = 0;

    if ( sp < nt )
 	return 1;
    else
	return 0;
  }
  else if ( win2k &&  "5.0" >< vers )
  {
    sp  = get_kb_item("SMB/CSDVersion");
    if ( sp )
    	sp   = int(ereg_replace(string:sp, pattern:".*Service Pack ([0-9]).*", replace:"\1"));
    else
	sp = 0;
    if ( sp < win2k )
 	return 1;
    else
	return 0;
  }
  else if ( xp &&  "5.1" >< vers )
  {
    sp  = get_kb_item("SMB/CSDVersion");
    if ( sp )
    	sp   = int(ereg_replace(string:sp, pattern:".*Service Pack ([0-9]).*", replace:"\1"));
    else
	sp = 0;
    if ( sp < xp )
 	return 1;
    else
	return 0;
  }
  else if ( win2003 &&  "5.2" >< vers )
  {
    sp  = get_kb_item("SMB/CSDVersion");
    if ( sp )
    	sp   = int(ereg_replace(string:sp, pattern:".*Service Pack ([0-9]).*", replace:"\1"));
    else
	sp = 0;

    if ( sp < win2003 )
 	return 1;
    else
	return 0;
  }
  else if ( vista &&  "6.0" >< vers)
  {
    sp  = get_kb_item("SMB/CSDVersion");
    if ( sp )
    	sp   = int(ereg_replace(string:sp, pattern:".*Service Pack ([0-9]).*", replace:"\1"));
    else
	sp = 0;

    if ( sp < vista )
 	return 1;
    else
	return 0;
  }
  else if ( win7 &&  "6.1" >< vers)
  {
    sp  = get_kb_item("SMB/CSDVersion");
    if ( sp )
    	sp   = int(ereg_replace(string:sp, pattern:".*Service Pack ([0-9]).*", replace:"\1"));
    else
	sp = 0;

    if ( sp < win7 )
 	return 1;
    else
	return 0;
  }
  else if (win8 && "6.2" >< vers)
  {
    sp  = get_kb_item("SMB/CSDVersion");
    if ( sp )
    	sp   = int(ereg_replace(string:sp, pattern:".*Service Pack ([0-9]+).*", replace:"\1"));
    else
	sp = 0;

    if ( sp < win8 ) return 1;
    else return 0;
  }
  else if (win81 && "6.3" >< vers)
  {
    sp = get_kb_item("SMB/CSDVersion");
    if ( sp )
    	sp   = int(ereg_replace(string:sp, pattern:".*Service Pack ([0-9]+).*", replace:"\1"));
    else sp = 0;

    if (sp < win81) return 1;
    else return 0;
  }

  return -1;
}

##
#
# Checks to see if the detected service pack is within a range of
# specified service packs.
#
# @param nt Service Pack range for Windows NT
# @param win2k Service Pack range for Windows 2000
# @param xp Service Pack range for Windows XP
# @param win2003 Service Pack range for Windows 2003
# @param vista Service Pack range for Windows Vista/2008
# @param win7 Service Pack range for Windows 7/2008 R2
# @param win8 Service Pack range for Windows 8/2012
# @param win10 Service Pack range for Windows 10
# @return   -1 if the version of Windows isn't one we check
#            0 if the service pack is outside the range
#            1 if the service pack is within the range
##
function hotfix_check_sp_range(nt, win2k, xp, win2003, vista, win7, win8, win81, win10)
{
  local_var os, vers, sp;
  local_var sp_ranges, splist, minsp, maxsp;

  vers = get_kb_item_or_exit('SMB/WindowsVersion');

  sp_ranges= make_array(
    'nt', nt,
    'win2k', win2k,
    'xp', xp,
    'win2003', win2003,
    'vista', vista,
    'win7', win7,
    'win8', win8,
    'win8.1', win81,
    'win10', win10
  );

  if ('4.0' >< vers)
    os = 'nt';
  else if ('5.0' >< vers)
    os = 'win2k';
  else if ('5.1' >< vers)
    os = 'xp';
  else if ('5.2' >< vers)
    os = 'win2003';
  else if ('6.0' >< vers)
    os = 'vista';
  else if ('6.1' >< vers)
    os = 'win7';
  else if ('6.2' >< vers)
    os = 'win8';
  else if ('6.3' >< vers)
    os = 'win8.1';
  else if ('10' >< vers)
    os = 'win10';
  if (isnull(os)) return -1;

  # Get the min and max SPs for the detected OS. Set
  # minsp to the smaller of the two values, and maxsp
  # to the larger of the two
  if (isnull(sp_ranges[os])) return -1;
  splist = split(sp_ranges[os], sep:',', keep:FALSE);
  if (max_index(splist) == 1)
  {
    minsp = int(splist[0]);
    maxsp = minsp;
  }
  else if (max_index(splist) == 2)
  {
    if (int(splist[0]) <= int(splist[1]))
    {
      minsp = int(splist[0]);
      maxsp = int(splist[1]);
    }
    else exit(1, 'The specified minimum service pack for '+os+' is greater than the maximum service pack.\n');
  }
  else exit(1, 'An invalid number of service packs was supplied for the range for '+os+'.\n');

  sp = get_kb_item("SMB/CSDVersion");
  if (sp)
    sp = int(ereg_replace(string:sp, pattern:'.*Service Pack ([0-9]+).*', replace:"\1"));
  else sp = 0;

  if (sp < minsp || sp > maxsp) return 0;
  return 1;
}

#-----------------------------------------------------------------------------
# hotfix_missing()
#
# Returns:
# -1 : Could not verify if the hotfix is installed (ie: lack of credentials)
#  0 : The hotfix is installed
#  1 : The hotfix is missing
#-----------------------------------------------------------------------------
function hotfix_missing(name)
{
 # KB test are disabled.
 return -1;
}

##
# This function gives hotfix scripts the opportunity to check if the bulletin
# has already been detected by a 3rd party patch management solution (SCCM,
# VMware Go, etc).
#
# Note that it should only be called if a third-party check is to be
# and can be done - it is guaranteed to call 'exit()'.
#
# @param bulletin The bulletin to check.
#
# @param kbs A list of Microsoft KBs associated with the bulletin.
#
# @param severity A string denoting which report function to use.
#
# @return n/a
##
function hotfix_check_3rd_party(bulletin, kbs, severity)
{
  local_var available_tools, port, tool, tool_name;
  local_var mskb, mskbs, pm_report, vuln;
  local_var key;

  available_tools = make_array();
  vuln = FALSE;

  #gather status for patches through the available patch management products
  foreach tool (keys(_pmtool_names))
  {
    if (isnull(get_kb_item("patch_management/"+tool))) continue;

    tool_name = _pmtool_names[tool];
    available_tools[tool_name] = FALSE;

    foreach mskb (kbs)
    {
      if (get_kb_item(tool+"/missing_patch/nt/kb/" + mskb))
      {

        if (defined_func("report_xml_tag") && !isnull(bulletin))
        {
          report_xml_tag(tag:bulletin, value:mskb);
          #set bulletin ID for patch diffing purpose
          replace_kb_item(name:tool+"/missing_patch/nt/bulletin/" + tolower(bulletin) ,value:TRUE);
        }

        available_tools[tool_name] = TRUE;
        vuln = TRUE;

        break;
      }
    }
  }

  # generate report
  if (!isnull(max_index(keys(available_tools))))
  {
    pm_report = 'The following patch management products report :\n';
    foreach key (keys(available_tools))
    {
      if (available_tools[key]) pm_report += '  ' + key + ' :  Vulnerable\n';
      else pm_report += '  ' + key + ' : NOT vulnerable\n';
    }
  }

  # reporting section
  if (isnull(get_kb_item("SMB/Registry/Enumerated")) && vuln)
  {
    port = get_kb_item("SMB/transport");
    if (isnull(port)) port = 445;

    pm_report += '\n\n*Nessus did not run local checks.\n';

    security_report_v4(port:port, extra:pm_report, severity:severity);

    if (!isnull(bulletin)) replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);

    exit(0);
  }
  else if (isnull(get_kb_item("SMB/Registry/Enumerated")) && !vuln && !isnull(pm_report))
    exit(0, pm_report);
  else
  {
    pm_report += '\n\n';
    hotfix_add_report(pm_report);
  }
}
