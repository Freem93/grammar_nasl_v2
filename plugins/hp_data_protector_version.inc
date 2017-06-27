# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# hp_data_protector_version.inc
# $Revision: 2.5 $
#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

global_var hp_data_protector_components;
global_var hp_data_protector_found_affected_os;
global_var hp_data_protector_os;

hp_data_protector_components = make_array(
  "core", "Core Server",
  "cell_server", "Cell Server",
  "cell_console", "Cell Console",
  "disk_agent", "Disk Agent",
  "media_agent", "Media Agent",
  "documentation", "Documentation",
  "autodr", "Auto DR",
  "vepa", "VE Agent",
  "emc", "EMC",
  "vmware_gre", "VMWARE-GRE",
  "sos", "SOS",
  "ssea", "SSEA",
  "sap_hana", "SAP HANA"
);

hp_data_protector_os = NULL;
hp_data_protector_found_affected_os = FALSE;

# Check if HP Data Protector is vulnerable
#
# @param fixed_internal_build Fixed internal build number (int).
# @param os Operating System ("windows", "linux", "solaris", or "hpux")
# @param os_version_pat Regex for matching applicable OS versions
# @param version_pat Affected version regex
# @param comp_patches Array with component fixes (e.g. array("cell_server", 706)
# @param patch_bundle patch bundle fix (int)
# @param severity Severity level
# @param port Reporting port
# @param patch_prefix used to override default patch prefix (DPWIN, PHSS, DPLNX, DPSOL)
# @return NULL if not affected 

function hp_data_protector_check(os, os_version_pat, version_pat, fixed_internal_build, comp_patches, patch_bundle, severity, port, patch_prefix)
{
  local_var vuln, comp, fix, comp_name, tmp, prefix, info, core_version, internal_build,
            comp_ver, comp_build, item, space_a, space_b, fix_str, internal_build_vuln;

  info = '';

  if(isnull(os))
  {
    err_print('hp_data_protector_check: missing os argument.');
    return NULL;
  }

  if(isnull(os_version_pat))
  {
    err_print('hp_data_protector_check: missing os_version_pat argument.');
    return NULL;
  }

  if(isnull(version_pat))
  {
    err_print('hp_data_protector_check: missing version_pat argument.');
    return NULL;
  }

  if(isnull(severity))
  {
    err_print('hp_data_protector_check: missing severity argument.');
    return NULL;
  }

  if(isnull(port))
  {
    err_print('hp_data_protector_check: missing port argument.');
    return NULL;
  }
 
  if(isnull(fixed_internal_build) && isnull(comp_patches) && isnull(patch_bundle))
  {
    err_print('hp_data_protector_check: missing fix / patch check information.');
    return NULL;
  }

  os = tolower(os);
  os -= "-";

  if(os == "windows")
    prefix = "DPWIN_";
  else if(os == "linux")
    prefix = "DPLNX_";
  else if(os == "solaris")
    prefix = "DPSOL_";
  else if(os == "hpux")
    prefix = "PHSS_";
  else
  {
    err_print('hp_data_protector_check: invalid os=', os);
    return NULL;
  }

  if(!isnull(patch_prefix)) prefix = patch_prefix + "_";

  # check that we are looking at an affected version
  if(!_hp_data_protector_is_affected_os(os:os, os_version_pat:os_version_pat)) return NULL;

  hp_data_protector_found_affected_os = TRUE;

  # we can't do any checks without this
  core_version = get_kb_item_or_exit("Services/data_protector/version");
  if(core_version !~ version_pat) return NULL;

  # compare against internal build number
  internal_build = get_kb_item("Services/data_protector/build");
  if (isnull(internal_build)) internal_build = '0';

  internal_build_vuln = FALSE;

  if(!isnull(fixed_internal_build))
  {
    if (typeof(fixed_internal_build) != "int")
      err_print("hp_data_protector_check: fixed_internal_build argument not of type int.");
    else
    {
      if(int(internal_build) < fixed_internal_build)
      {
        info += '\n  Internal build number : ' + internal_build +
                '\n  Fixed internal build  : ' + fixed_internal_build + '\n';
        internal_build_vuln = TRUE;
      }
    } 
  }
 
  tmp = get_kb_item("Services/data_protector/patch_info_is_str");

  # Added recommend patch bundle to report if available, if we are already vulnerable
  if(!isnull(patch_bundle) && isnull(tmp) && info != '')
  {
    fix_str = _format_patch_str(prefix:'BDL', digits:patch_bundle);
    info += '\n  Required patch bundle : ' + fix_str + '\n';
  }

  # if there is a bundle patch installed, compare it against expected version
  if(!isnull(tmp) && !isnull(patch_bundle))
  {
    vuln = FALSE;

    if (typeof(patch_bundle) != "int")
      err_print("hp_data_protector_check: patch_bundle argument not of type int.");
    else
    {
      item = eregmatch(pattern:"\(BDL[0]*([1-9][0-9]*)\)", string:tmp);
   
      if(!isnull(item) && !isnull(item[1]))
      {
        tmp = _format_patch_str(prefix:'BDL', digits:item[1]);
        if(int(item[1]) < patch_bundle)
          vuln = TRUE;
      }
    }

    if(vuln)
    {
      fix_str = _format_patch_str(prefix:'BDL', digits:patch_bundle);
      info += '\n  Patch bundle installed : ' + tmp +
              '\n  Fixed patch bundle     : ' + fix_str + '\n';
    }
  }
  
  # find any unpatched components and list them on report
  if(!isnull(comp_patches) && !isnull(get_kb_item("Services/data_protector/patch_info_is_str")))
  {
    foreach comp (keys(comp_patches))
    {
      vuln = FALSE;
      fix = comp_patches[comp];
      if (typeof(fixed_internal_build) != "int")
      {
        err_print("hp_data_protector_check: " + comp + " component fix not of type int.");
        continue;
      }

      comp_name = hp_data_protector_components[comp];
      if(isnull(comp_name))
      {
        err_print('hp_data_protector_check: invalid component name=', comp);
        continue;
      }
      
      comp_ver = get_kb_item("Services/data_protector/" + comp + "/Version");
      comp_build = get_kb_item("Services/data_protector/" + comp + "/Build"); 

      # verify that component is installed.  This may not always be possible
      if(isnull(comp_ver) && isnull(comp_build)) continue;

      if(isnull(comp_build))
        comp_build = 'MR';
      else
      {
        item = eregmatch(pattern:prefix +"[0]*([1-9][0-9]*)($|[^0-9])", string:comp_build);
        if(isnull(item) || isnull(item[1])) comp_build = 'MR';
        else comp_build = int(item[1]);
      }

      # only flag modules missing build information if we are running a
      # vulnerable internal build number
      if (comp_build == 'MR' && internal_build_vuln)
        vuln = TRUE;
      else if(comp_build != 'MR' && comp_build < fix)
        vuln = TRUE;

      if(vuln)
      {
        fix_str = _format_patch_str(prefix:prefix, digits:fix);
 
        space_a = '';
        space_b = '';
        tmp = 11 - strlen(comp_name);
        if(tmp > 0) space_a = crap(data:" ", length:tmp);
        if(tmp < 0) space_b = crap(data:" ", length:(tmp*-1));

        if(!isnull(comp_ver) && comp_ver != '') 
          info += '\n  ' + comp_name + ' version ' + space_a + ': ' + comp_ver;
        info += '\n  ' + comp_name + ' build   ' + space_a + ': ' + comp_build +
                '\n  Fixed build / patch ' + space_b + ': ' + fix_str + '\n'; 
      }
    }
  }

  if(info == '') return NULL;

  security_report_v4(port:port, extra:info, severity:severity);
  exit(0);
}
 
# call after hp_data_protector_check_vuln calls to exit with
# proper audit trail
# @param port Port
# @return Doesn't return 
function hp_data_protector_check_exit(port)
{
  local_var core_version;
  core_version = get_kb_item_or_exit("Services/data_protector/version");

  if(isnull(port))
  {
    err_print('hp_data_protector_check_exit: invalid port=', port);
    port = 0;
  }

  if(!hp_data_protector_found_affected_os)
    exit(0, "The remote host is not running an affected operating system.");

  audit(AUDIT_LISTEN_NOT_VULN, "HP Data Protector", port, core_version);
}

function _hp_data_protector_get_os_str()
{
  local_var tmp, item;

  # avoid re-parsing OS string
  if(isnull(hp_data_protector_os))
  {
    hp_data_protector_os = make_array();

    tmp = get_kb_item("Services/data_protector/patch_info_str");
    item = eregmatch(pattern:'-[oO][sS] "([^"]+)"', string:tmp); 
    if(isnull(item) || isnull(item[1]))  
    {  
      tmp = get_kb_item("Services/data_protector/patch_info_is_str");
      item = eregmatch(pattern:'-[oO][sS] "([^"]+)"', string:tmp); 
    }
    if(!isnull(item) && !isnull(item[1]))
    {
      tmp = tolower(item[1]);

      item = eregmatch(pattern:"^microsoft .+ wnt-([0-9.]+)-[swu]$", string:tmp);
      if(!isnull(item) && !isnull(item[1]))
      {
        hp_data_protector_os["microsoft"] = item[1];
        return hp_data_protector_os;
      }
      item = eregmatch(pattern:"^gpl .+ linux-(.+)$", string:tmp);
      if(!isnull(item) && !isnull(item[1]))
      {
        hp_data_protector_os["linux"] = item[1];
        return hp_data_protector_os;
      }
      item = eregmatch(pattern:"^hp .+ hp-ux-([0-9.]+)$", string:tmp);
      if(!isnull(item) && !isnull(item[1]))
      {
        hp_data_protector_os["hpux"] = item[1];
        return hp_data_protector_os;
      }
      item = eregmatch(pattern:"^sun .+ solaris-([0-9.]+)$", string:tmp);
      if(!isnull(item) && !isnull(item[1]))
      {
        hp_data_protector_os["solaris"] = item[1];
        return hp_data_protector_os;
      }
    }
  }

  return hp_data_protector_os;
}

function _hp_data_protector_is_affected_os(os, os_version_pat)
{
  local_var winver, winver1, item, os_ver, os_map;

  os_map = _hp_data_protector_get_os_str();

  os_ver = '';
 
  if(os == 'hpux')
  {
    os_ver = get_kb_item("Host/HP-UX/version");
    if(isnull(os_ver)) os_ver = os_map["hpux"];
  }
  else if(os == 'solaris')
  {
    os_ver = get_kb_item("Host/Solaris/Version");
    if(isnull(os_ver)) os_ver = os_map["solaris"];
  }
  else if(os == 'linux')
  {
    os_ver = get_kb_item("Host/RedHat/release");
    if(isnull(os_ver))
      os_ver = get_kb_item("Host/SuSE/release");
    if(isnull(os_ver)) os_ver = os_map["linux"];
  }
  else if(os == 'windows')
  {
    winver = get_kb_item("SMB/WindowsVersion");
    winver1 = get_kb_item("Host/OS/smb");
    os_ver = winver;
    if (isnull(winver) && !isnull(winver1))
    {
      item = eregmatch(pattern:" ([0-9.]+)$", string:winver1);
      if (!isnull(item)) os_ver = item[1];
    }
    if(isnull(os_ver)) os_ver = os_map["windows"];
  }

  if (isnull(os_ver) || os_ver == '') return FALSE;

  if (os_ver =~ os_version_pat) return TRUE;
  else return FALSE;
}

function _format_patch_str(prefix, num_digits, digits)
{
  local_var pad, pad_len;

  if(isnull(num_digits)) num_digits = 5;

  pad = "";
  pad_len = num_digits - strlen(string(digits));
  if(pad_len > 0) pad = crap(data:"0", length:pad_len);

  return prefix + pad + digits;
}

