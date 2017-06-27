##
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# f5_func.inc
#
# $Revision: 1.8 $
##

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# External use globals
global_var BIGIP_MOD_KB_BASE,BIGIP_LT_VER,BIGIP_AT_VER_LT_HF,BIGIP_AT_VER_AT_HF,BIGIP_AT_VER_GT_HF,BIGIP_GT_VER;

# Internal use globals
global_var __BIGIP_MODULES_CHECKED,__BIGIP_MODULES_AFFECTED,__BIGIP_SOLUTION_STRING,__BIGIP_VALID_MODS;

##
# BIGIP Module kb root, the status (enabled / disabled) of each module
# is stored at Host/BIG-IP/Modules/<module_name>
#
# module_name should be one of the strings in __BIGIP_VALID_MODS
##
BIGIP_MOD_KB_BASE = "Host/BIG-IP/modules";

##
# Valid BIGIP module strings
# Might use this for error checking
# at some point, currently unused
##
__BIGIP_VALID_MODS = make_list(
  "GTM", #BIG-IP GTM
  "LTM", #BIG-IP LTM
  "ASM", #BIG-IP ASM
  "AM",  #BIG-IP AAM
  "AFM", #BIG-IP AFM
  "LC",  #BIG-IP LINK CONTROLLER
  "WAM", #BIG-IP WEBACCELERATOR
  "WOM", #BIG-IP WAN OPTIMIZATION
  "AVR", #BIG-IP ANALYTICS
  "PEM", #BIG-IP PEM
  "PSM", #BIG-IP PSM
  "APM"  #BIG-IP APM
);


##
# Modified by function calls, a list of modules
# found to be enabled that version checking 
# was done for
#
# @remark modified by function calls
# @remark used in report generation
##
__BIGIP_MODULES_CHECKED = make_list();

##
# Any module that was found to be active
# and was found to be affected during 
# version checking is added to this array
# with a list of its unaffected versions
#
# @remark modified by function calls
# @remark used in report generation
##
__BIGIP_MODULES_AFFECTED = make_array();

##
# The BIG IP solution we're currently
# checking for
#
# @remark modified by function calls
# @remark used in report generation
##
__BIGIP_SOLUTION_STRING = "";

##
# Sometimes F5 will list a security
# advisory like this:
# Affected   : 11.1.0-11.5.1
# Unaffected : 11.0.0
# 
# This means they've issued the 
# advisory but have not fixed it
# yet.  We check for this and
# alert the user to the situation
# with this flag.  We check this
# by seeing if the user's version
# is greater than any of the
# unaffected versions listed
#
# @remark modified by function calls
# @remark used in report generation
# @see _bigip_nofix_check()
##
__BIGIP_NOFIX_FLAG = TRUE;


##
# Return codes for _bigip_check_hotfixed
##
BIGIP_LT_VER       = -2;  # Version less than specified version
BIGIP_AT_VER_LT_HF = -1;  # Version at specified version but with lesser hotfix
BIGIP_AT_VER_AT_HF =  0;  # Version at specified version with exactly hotfix
BIGIP_AT_VER_GT_HF =  1;  # Version at specified version with greater hotfix
BIGIP_GT_VER       =  2;  # Version at greater version than specified version


##
# Checks to see if there are "no fixes" or the only option is to
# "downgrade" to a previous version, given a list of unaffected
# 
# @param unaffected a list of vspecs that specify unaffected BIG-IP 
#                   versions
#
# @return TRUE  if any version specified by unaffected is greater 
#               than the BIG-IP version
#         FALSE otherwise
##
function _bigip_nofix_check(unaffected)
{
  local_var vspec,ver,chk;
  foreach vspec (unaffected)
  {
    # Get hi end of a range
    if (vspec =~ "-")
    {
      vspec = split(vspec,sep:"-",keep:FALSE);
      vspec = vspec[1]; # Hi end
    }
    # Check to see if vspec >= systems version/hotfix
    vspec = _bigip_ver_parse(ver:vspec);
    if (vspec['hotfix'] != NULL)
    {
      chk = _bigip_check_hotfixed(tver:vspec['version'],tfix:vspec['hotfix']);
      # Seems we have a fix
      if (chk < BIGIP_AT_VER_AT_HF)
        return FALSE;
    }
    else
    {
      # No hotfix or some none granular vspec like "11" or "11.2"
      ver = get_kb_item("Host/BIG-IP/version");
      ver = _bigip_trim_ver(ver:ver,to:vspec["version"]);
      if (ver_compare(ver:ver,fix:vspec["version"],strict:FALSE) <= 0)
        return FALSE;
    }
  }
  return TRUE;
}

##
# Checks a given version specification or range for valid characters
# and checks each individual version within for a valid version string
#
# @param vspec string containing version/hotfix information
#
# @remark Supports ranges or individual entries. A range may only
#         consist of two versions separated by a dash.
#
# @return TRUE if vspec is a single version with valid chars/format OR
#                 vspec is a range containing valid versions
#         FALSE otherwise
##
function _bigip_vspec_valid(vspec)
{
  # Char restriction
  if (vspec =~ "[^(HF)0-9\-.]")
    return FALSE;
  # Range check
  if ("-" >< vspec)
  {
    vspec = split(vspec,sep:"-",keep:FALSE);
    if (len(vspec) != 2) return FALSE;
    return _bigip_vspec_valid(vspec:vspec[0]) && _bigip_vspec_valid(vspec:vspec[1]);
  }
  if (vspec !~ "^\d+(\.\d+)+$" && vspec !~ "^\d+\.\d+\.\d+HF\d+$")
    return FALSE;
  return TRUE;
}

##
# Parses a version specification's version and hotfix into separate values
#
# @param ver string containing version/hotfix information
#
# @remark Do not pass this a range
#
# @return an array with "version" returning the version string, with
#         "hotfix" containing the hotfix number (null if no hotfix)
##
function _bigip_ver_parse(ver)
{
  local_var hf,bver;

  # No hotfix nothing to do
  if (ver !~ "HF\d+")
    return make_array("version",ver,"hotfix",NULL);

  hf = eregmatch(pattern:"HF(\d+)",string:ver);
  hf = int(hf[1]);
  bver = ereg_replace(pattern:"HF\d+",replace:"",string:ver);
  return make_array("version",bver,"hotfix",hf);
}

##
# Trims version ver down to the tuple length of version to
#
# @param ver string containing version/hotfix information
# @param to string containing version/hotfix information
#
# @remark Example: _bigip_trim_ver("9.0.2.3.4.2", "11.2.3")
#                  would return "9.0.2"
#
# @return a string of the first tnum tuples of ver, tnum being the
#           number of tuples in to
#         ver unchanged if tnum has more tuples than ver
##
function _bigip_trim_ver(ver,to)
{
  local_var tnum,vtuples,newver,i;
  tnum     = len(object:split(to,sep:"."));
  vtuples  = split(ver,sep:".",keep:FALSE);
  if (tnum > len(object:vtuples)) return ver;

  newver = make_list();
  for(i = 0; i < tnum; i++)
  {
    newver[i] = vtuples[i];
  }
  return join(newver,sep:".");
}

##
# Returns an integer comparing the state of the remote system's
# BIGIP software version and hotfix number to the target fix and
# hotfix number
#
# @remark Hotfix checking is STRICT ie 11.0HF9 is invalid and 
#         BIG-IP will not specify a hotfixed version like this
#         on purpose, it's always 3 tuples: x.x.xHFx
#
# @param tver string containing target version information
# @param tfix string containing target hotfix information
#
#
# @return BIGIP_GT_VER       if version >  target version
#         BIGIP_AT_VER_LT_HF if version == target version && hotfix <  target hotfix
#         BIGIP_AT_VER_AT_HF if version == target version && hotfix == target hotfix
#         BIGIP_AT_VER_GT_HF if version == target version && hotfix >  target hotfix
#         BIGIP_LT_VER       if version <  target version
##
function _bigip_check_hotfixed(tver,tfix)
{
  local_var ver,fix,stat;
  ver  = get_kb_item("Host/BIG-IP/version");
  fix  = get_kb_item("Host/BIG-IP/hotfix");
  stat = ver_compare(ver:ver,fix:tver,strict:TRUE);
  fix  = int(fix);
  tfix = int(tfix);
  if (stat ==  -1) return  BIGIP_LT_VER;       # We're at a lesser version
  if (stat ==   1) return  BIGIP_GT_VER;       # We're at a greater version
  if (fix == tfix) return  BIGIP_AT_VER_AT_HF; # We're at tver, with a hotfix == tfix
  if (fix >  tfix) return  BIGIP_AT_VER_GT_HF; # We're at tver, with a hotfix >  tfix
  else             return  BIGIP_AT_VER_LT_HF; # We're at tver, with a hotfix <  tfix
}

##
# Determine if the version of BIGIP software on a remote system is
# inclusively between a given version range 
#
# @param vspec   string containing version/hotfix range information
# @param chkaff bool are we checking for affected? false 
#                    implies checking unaffected
#
#
# @return FALSE if version less than low range OR
#                  version greater than high range
#         TRUE otherwise
##
function _bigip_inclusively_between(vspec,chkaff)
{
  local_var lo,hi,tmp,ver,hf,lvl;
  ver = get_kb_item("Host/BIG-IP/version");
  vspec = split(vspec,sep:"-",keep:FALSE);
  lo = _bigip_ver_parse(ver:vspec[0]);
  hi = _bigip_ver_parse(ver:vspec[1]);

  # Are we outside the low range?
  if (lo["hotfix"] != NULL) 
  {
    tmp = _bigip_check_hotfixed(tver:lo["version"],tfix:lo["hotfix"]);
    # Fully outside of range
    if (tmp == BIGIP_LT_VER || tmp == BIGIP_AT_VER_LT_HF) 
      return FALSE;
  }
  else
  {
    if (ver_compare(ver:ver,fix:lo["version"],strict:FALSE) < 0)
      return FALSE;
  }

  # Are we outside of the hi range?
  if (hi["hotfix"] != NULL)
  {
    tmp = _bigip_check_hotfixed(tver:hi["version"],tfix:hi["hotfix"]);
    # Fully outside of range
    # When checking for "affected", we're also out of this range if 
    # the remote systems HF is greater than the hi end's HF (when 
    # at the same base version). However, if you're checking for
    # unaffected, then treat a HF greater than the hi end's HF
    # as in this range because hotfixes are cumulative 
    # ie HF8 has all the fixes for HF1 through HF8 so it is equivalent
    # to HF1-HF7 when checking for "fixed" or "not affected" versions
    if (tmp == BIGIP_GT_VER || (chkaff && tmp == BIGIP_AT_VER_GT_HF))
      return FALSE;
  }
  else
  {
    # Trim ver to the length of hiv, if hi version is
    # LESS granular than ver, then consider versions
    # with more granularity to be in that range, ie:
    # hiv = 11
    # ver = 11.3.2
    # return TRUE aka consider 11.3.2 at version 11
    ver = _bigip_trim_ver(ver:ver,to:hi["version"]);
    if (ver_compare(ver:ver,fix:hi["version"],strict:FALSE) > 0)
      return FALSE;
  }
  return TRUE;
}

##
# Determine if the version of BIGIP software on a remote system is
# within the version range or at the version level specified by 
# vspec.
#
# @remark Examples (Assume BIGIP Version is 10.1.2HF9):
#    _bigip_vspec_check("10",TRUE) returns TRUE
#    _bigip_vspec_check("10.2",TRUE) returns FALSE
#    _bigip_vspec_check("9.0.0-10.1.2HF8",FALSE) returns TRUE 
#    (HF9 treated as HF8 when chkaff = FALSE)
#    _bigip_vspec_check("9.0.0-10.1.2HF8", TRUE) returns FALSE 
#    (H9 treated as greater than H8 when chkaff = TRUE)
#
# @param vspec  string containing version/hotfix information
# @param chkaff bool are we checking for affected? false 
#                    implies checking unaffected
#
# @return FALSE if version not within range or at version level
#               specified by vspec
#         TRUE otherwise
##
function _bigip_vspec_check(vspec,chkaff)
{
  local_var tmp,ver;
  ver = get_kb_item("Host/BIG-IP/version");

  # Version specification is range
  if ("-" >< vspec)
  {
    return _bigip_inclusively_between(vspec:vspec,chkaff:chkaff);
  }
  else # Version spec is single version
  {
    vspec = _bigip_ver_parse(ver:vspec);
    if (vspec["hotfix"] != NULL)
    {
      tmp = _bigip_check_hotfixed(tver:vspec["version"],tfix:vspec["hotfix"]);
      # Below or at Hotfix, for checking "affected"
      if (chkaff  && (tmp == BIGIP_AT_VER_AT_HF || tmp == BIGIP_AT_VER_LT_HF))
        return TRUE;
      # Above or at hotfix, for checking "unaffected"
      if (!chkaff && (tmp == BIGIP_AT_VER_GT_HF || tmp == BIGIP_AT_VER_AT_HF))
        return TRUE;
    }
    else
    {
      # Make ver have no more version tuples than vspec["version"]
      tmp = _bigip_trim_ver(ver:ver,to:vspec["version"]);
      # No hotfix, just use ver_compare
      if (vspec["hotfix"] == NULL && ver_compare(ver:tmp,fix:vspec["version"],strict:FALSE) == 0)
        return TRUE;
    }
  }
  # Implicitly did not match any vspec
  return FALSE;
}

##
# Determine if a specific product module is affected via list of
# of affected and unaffected versions.
#
# @remark Modifies __BIGIP_MODULES_CHECKED
# @remark Examples (Assume BIGIP Version is 10.1.2HF9 and GTM enabled):
#                  a = ["10","7-9.0.0HF2"]
#                  u = ["10.1.2HF7"]
#                  bigip_mod_is_affected(prodmod:"GMT",unaffected:u,affected:a)
#                  returns FALSE -> HF9 is equivalent to HF7 for 10.1.2
#
#                  a = ["10","7-9.0.0HF2"]
#                  u = ["10.0.0HF7"]
#                  bigip_mod_is_affected(prodmod:"GMT",unaffected:u,affected:a)
#                  returns TRUE -> Affected 10 implies all 10 versions are
#                                  are affected unless otherwise stated.
#                                  I've never actually seen BIGIP list an
#                                  advisory like this, they are always very
#                                  specific with affected and general with
#                                  unaffected
# @param prodmod    a module associated with a specific BIG-IP product
#                   the module should be the strings in __BIGIP_VALID_MOD
#                   the module is checked to be enabled by looking at the
#                   kb item BIGIP_MOD_KB_BASE/<prodmod> 
# @param unaffected list of strings containing version/hotfix
#                   information that defines the set and ranges
#                   of unaffected BIGIP versions
# @param affected   list of strings containing version/hotfix
#                   information that defines the set and ranges
#                   of affected BIGIP versions
#
# @return FALSE if module is not enabled or not affected
#         TRUE otherwise
##
function bigip_mod_is_affected(prodmod,unaffected,affected)
{
  local_var vspec,tmp;
  # Check if the product module is enabled
  if (empty_or_null(get_kb_item(BIGIP_MOD_KB_BASE+"/"+prodmod))) return FALSE;

  # Module enabled, we are doing checks for it
  tmp = max_index(__BIGIP_MODULES_CHECKED);
  __BIGIP_MODULES_CHECKED[tmp] = prodmod;

  # Check if we are explicitly unaffected
  foreach vspec (unaffected)
  {
    tmp = _bigip_vspec_check(vspec:vspec,chkaff:FALSE);
    if (tmp) return FALSE;
  }
  # Check if we are explicitly affected
  foreach vspec (affected) 
  {
    tmp = _bigip_vspec_check(vspec:vspec,chkaff:TRUE);
    if (tmp)  return TRUE;
  }
  # Implicitly unaffected
  return FALSE;
}

##
# Determine if a remote BIGIP host is affected via a vulnerability matrix (vmatrix)
# of affected and unaffected versions.
# @param  vmatrix an object with a structure similar to:
#         make_array(
#             "GTM", make_array(
#               "affected",   make_list("10.1.2HF9","9.0.0-9.1.2"),
#               "unaffected", make_list("11","10.1.2HF10-10.1.2HF12")
#             ),
#             "LTM", make_array(
#               "affected",   make_list("10.1.2HF9","8.0.0-8.2.2"),
#               "unaffected", make_list("8.2.2HF1","11","10.1.2HF10-10.1.2HF12")
#             ),
#             ... ect ...
#          );
#
# @return FALSE if the BIGIP host is not affected
#         TRUE otherwise
##
function bigip_is_affected(vmatrix,sol)
{
  local_var p,u,a,rv,tmp;
  rv = FALSE;

  # For reporting
  __BIGIP_MODULES_CHECKED  = make_list();
  __BIGIP_MODULES_AFFECTED = make_array();
  __BIGIP_SOLUTION_STRING  = sol;
  # Assume no fix until nofix check tells us there is one
  __BIGIP_NOFIX_FLAG       = TRUE; 

  foreach p (keys(vmatrix))
  {
    u = vmatrix[p]["unaffected"];
    a = vmatrix[p]["affected"];
    if (bigip_mod_is_affected(prodmod:p,unaffected:u,affected:a))
    {
      __BIGIP_MODULES_AFFECTED[p] = u;
      # Set the nofix flag if we still believe there is no fix
      if (__BIGIP_NOFIX_FLAG)
        __BIGIP_NOFIX_FLAG = _bigip_nofix_check(unaffected:u);
      rv = TRUE;
    }
  }
  return rv;
}

##
# Generates a report about affected BIGIP products based on the
# last call to bigip_is_affected(...)
#
# @return A string with the report information gathered during 
#         the last call to bigip_is_affected(....). If no modules
#         were found to be affected this function returns NULL;
##
function bigip_report_get() 
{
  local_var rv,hf,pfix,pad,p;

  if (empty_or_null(__BIGIP_MODULES_AFFECTED))
    return NULL;
  pfix = '\n  ';
  rv =
    pfix+'BIGIP version               : '+get_kb_item("Host/BIG-IP/version");
    #prfx+'Unaffected Versions for XXX : '
  hf = get_kb_item("Host/BIG-IP/hotfix");
  if (!isnull(hf) && hf != "0")
    rv += pfix+'Hotfix                      : '+hf;
  rv += pfix+'Modules affected            : '+join(keys(__BIGIP_MODULES_AFFECTED),sep:" / ");
  if (__BIGIP_NOFIX_FLAG)
    rv += pfix+'Note                        : There are currently no fixes offered by F5 for this issue.';
  foreach p (keys(__BIGIP_MODULES_AFFECTED))
  {
    pad = "";
    if (strlen(p) < 3) pad += " ";
    rv += pfix+'Unaffected versions for '+p+pad+" : "+join(__BIGIP_MODULES_AFFECTED[p],sep:" / ");
  }
  return rv+'\n';
}

##
#  Simple getter for __BIGIP_MODULES_CHECKED
#
# @return the list of modules checked from the last call of
#         bigip_is_affected(....) as a string separated by ' / '
##
function bigip_get_tested_modules()
{
  return join(__BIGIP_MODULES_CHECKED,sep:" / ");
}

##
# Tries to parse hotfix number from rawver (contents of /VERSION on the system)
# base version is required because the format changed with version 11.5.1
# 
# @param basever a string containing the base version of BIG-IP (extract by ssh_get_info)
# @param rawver  a string containing the output from cat /VERSION
#
# @return 0        if no hotfix
#         NULL     if error
#         HF digit if hotfix level was parsed
##
function bigip_parse_hotfix(basever, rawver)
{
  local_var hotfixed,hf;

  if (isnull(rawver)  || rawver  == "") return NULL;
  if (isnull(basever) || basever == "") return NULL;

  # ver >=11.5.1 Hotfix is first number of "Build"
  if (ver_compare(ver:basever,fix:"11.5.1",strict:FALSE) >= 0)
  {
    hf = eregmatch(pattern:"[Bb]uild\s*:?\s*(\d+)(\.\d+)+($|\n|\r\n)",string:rawver);
    if (isnull(hf)) return NULL;
    hotfixed = hf[1];
  }
  # ver < 11.5.1 Hotfix is in "Edition"
  else
  {
    # Hotfix 0 will be something like "Edition: Final"
    # If it has a hotfix, will be something like "Edition: Hotfix HF1"
    hf = "0";
    if (rawver =~ "[Hh]otfix")
    {
      hf = eregmatch(pattern:"[Ee]dition\s*:?\s*(Engineering)?\s*Hotfix HF(\d+)($|\n|\r\n)",string:rawver);
      # Couldn't parse HF
      if (isnull(hf)) return NULL;
      hf = hf[2];
    }
    hotfixed = hf;
  }
  return hotfixed;
}

##
# Tries to parse the enabled module list from raw command
# output, the commands that can be parsed are:
#
# "tmsh list /sys provision" (versions after 10)
#
#   --and--
#
# "bigpipe db show | grep -i provision.CPU" (versions before 10)
#
# ssh_get_info tries one of these commands and stores it to the
# kb
#
# @param rawmod a string containing the output from a command
#
# @return a list of strings specifying the modules enabled
#         NULL if there was an error parsing
##
function bigip_parse_enabled_modules(rawmod)
{
  local_var mods, mod, modlist, modnum;

  if (isnull(rawmod) || rawmod == "") return NULL;

  modlist = make_list();
  modnum  = 0;

  # Remove \r
  rawmod = ereg_replace(pattern:'\r', replace:"",string:rawmod);
  # We're dealing with bigpipe output
  if ("Provision.CPU" >< rawmod)
  {
    mods = split(rawmod,sep:'\n',keep:FALSE);
    foreach mod (mods)
    {
      mod = eregmatch(pattern:"^Provision\.CPU\.(.*)\s+=\s+(\d+)$",string:mod);

      if (isnull(mod)) continue;

      # Module present, but not provisioned (enabled)
      if (mod[2] == "0") continue;

      mod = toupper(mod[1]);

      # This isn't a module, its the percent of the CPU not provisioned
      if (mod == "HOST") continue;

      modlist[modnum++] = mod;
    }
  }
  # We're dealing with tmsh output
  else if (rawmod =~ "sys\s+provision\s+[A-Za-z]+\s+{")
  {
    mods = split(rawmod,sep:"}",keep:TRUE);
    foreach mod (mods)
    {
      if (mod =~ "\s+level\s+.*\s+")
      {
        mod = ereg_replace(pattern:"(^\n|\n$)",replace:"",string:mod);
        mod = eregmatch(pattern:"^sys\s+provision\s+(.*)\s+{",string:mod);
        if (isnull(mod)) continue;
        mod = toupper(mod[1]);
        modlist[modnum++] = mod;
      }
    }
  } else return NULL; # Some kind of error or change in output
  return modlist;
}
