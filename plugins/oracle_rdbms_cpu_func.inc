#-*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# oracle_rdbms_cpu_func.inc
# $Revision: 1.19 $
#

include("audit.inc");

UNKNOWN_TNSLSNR =
  'The remote host operating system could not be identified based on the\n'+
  'TNSLSNR string.  If you know what operating system is installed on the\n' +
  'remote host, please send this signature and the name of the remote\n' +
  'operating system to os-signature@nessus.org :\n\n';

# Function to extract the OS that oracle is running on by checking the
# oracle_tnslsnr/port/version KB item.
# Several retrieved from http://blogs.conus.info/node/42
function get_oracle_os(tnslsnr)
{
  local_var os;

  os = NULL;

  # Sometimes the string will contain TNSLSNR, other times it will
  # contain TNS.  To simplify things, replace TNSLSNR with TNS
  if ('TNSLSNR' >< tnslsnr) tnslsnr = str_replace(string:tnslsnr, find:'TNSLSNR', replace:'TNS');

  if ('TNS for 32-bit Windows' >< tnslsnr)
    os = 'win32';
  else if ('TNS for 64-bit Windows' >< tnslsnr)
    os = 'win64';
  else if ('TNS for Linux' >< tnslsnr)
    os = 'nix';
  else if ('TNS for HPUX' >< tnslsnr)
    os = 'hpux';
  else if ('TNS for IBM/AIX' >< tnslsnr)
    os = 'aix';
  else if ('TNS for MacOS X Server' >< tnslsnr)
    os = 'macosx';
  else if ('TNS for Solaris' >< tnslsnr)
    os = 'solaris';
  else
  {
    set_kb_item(name:"Oracle/Host/OS/unknown", value:"TRUE");
    os = 'unknown';
  }
  return os;
}

function get_oracledb_host_os_and_port()
{
  local_var os, port, arch;
  os = get_kb_item_or_exit('Host/OS');
  if ('windows' >< tolower(os))
  {
    arch = get_kb_item_or_exit("SMB/ARCH");
    port = get_kb_item("SMB/transport");
    if (!port) port = 445;
    if ("x64" >< arch)
      os = 'win64';
    else
      os = 'win32';
  }
  else
  {
    port = 0;
    if ('linux' >< tolower(os))
      os = 'linux';
    else if ('AIX' >< os)
      os = 'aix';
    else if ('Solaris' >< os)
      os = 'solaris';
    else if ('HP-UX' >< os)
      os = 'hpux';
    else if('Mac OS X' >< os)
      os = 'macosx';
    else os = 'nix';
  }
  return (make_array('port', port, 'os', os));
}

# Function to extract the Oracle version by checking the
# oracle_tnslsnr/port/version KB item.
function get_oracle_version(tnslsnr)
{
  local_var ret, version;

  version = NULL;
  version = ereg_replace(string:tnslsnr, pattern:"^TNS(LSNR)? for .*: Version ([0-9\.]+).*", replace:"\2");

  return version;
}

##
# Finds Oracle databases
#
# @param compid The component to look for
# @param patchset If specified, look for the patchset
# @return ret [Array] An array of oracle products
#             NULL if no products were found
##
function find_oracle_databases()
{
  local_var ret, res, path, ohome, arch;
  local_var oracle_homes, components, version, highversion;
  local_var patchsets, patch, component;
  local_var sid, sids, temp;
  ret = make_array();

  oracle_homes = query_scratchpad("SELECT path, name, arch FROM oracle_homes");
  if (!max_index(oracle_homes)) exit(1, 'Failed to get any Oracle homes from the scratchpad.');
  foreach res (oracle_homes)
  {
    path = res['path'];
    ohome = res['name'];
    arch = res['arch'];
    # It is only possible to have one Oracle database in a given home, so we should only get one result
    components = query_scratchpad("SELECT version, comp_name FROM oracle_components WHERE ohome=? AND comp_id=?;", path, 'oracle.server');
    if (components)
    {
      version = components[0]['version'];
      highversion = version;
      patchsets = query_scratchpad("SELECT version FROM oracle_components WHERE ohome=? AND comp_id=?;", path, 'oracle.patchset.db');
      foreach patch (patchsets)
      {
        version = patch['version'];
        # I've only seen this once, but in cases where the version ends in non-numeric
        # characters, strip them out of the version number
        if (version =~ '^[0-9\\.]+[a-zA-Z]+$')
          version = ereg_replace(pattern:'^([0-9\\.]+).*$', string:version, replace:"\1");
        if (ver_compare(ver:version, fix:highversion) > 0)
          highversion = version;

      }
      ret[ohome]['version'] = highversion;
      ret[ohome]['compname'] = components[0]['comp_name'];
      ret[ohome]['path'] = path;
      ret[ohome]['arch'] = arch;

      # Grab the SIDs
      sids = query_scratchpad("SELECT sid FROM oracle_db_sids WHERE ohome=?;", path);
      if (sids)
      {
        temp = make_list();
        foreach sid (sids)
          temp = make_list(temp, sid['sid']);
        ret[ohome]['sids'] = join(temp, sep:',');
      }
    }
  }
  if (max_index(keys(ret)) > 0) return ret;
  return NULL;
}

# Function to check if the patch has been applied.
# Returns :
#  PatchID if patch is installed
#  NULL if patch is not installed
#  -1 if Patches are not available for the OS
function check_oracle_database(patches, low_risk, high_risk)
{
  local_var os, source, port, tnslsnr, lsnrversion, res, install, s;
  local_var sids, sid, ohome, installs, ver, vuln, missing, dbversion, report;
  local_var rdbms_patchlevel, ojvm_patchlevel, ojvm, fixpatchlevel;
  local_var osandport;
  os = NULL;

  # First try to get the patches by querying the DB
  if (get_kb_item("Oracle/RDBMS/Patches/Remote"))
  {
    source = "  SID                  : ";
    port = get_service(svc:"oracle_tnslsnr", default:1521, exit_on_fail:TRUE);
    tnslsnr = get_kb_item_or_exit("oracle_tnslsnr/"+port+"/version");

    if (isnull(os))
      os = get_oracle_os(tnslsnr:tnslsnr);
    lsnrversion = get_oracle_version(tnslsnr:tnslsnr);
    ver = split(lsnrversion, sep:'.', keep:FALSE);

    sids = get_kb_list("Oracle/"+port+"/*/RDBMS Patch Level");
    foreach sid (keys(sids))
    {
      rdbms_patchlevel = sids[sid];
      sid = sid - ("Oracle/" + port + "/");
      sid = sid - "/RDBMS Patch Level";
      installs[sid]["version"] = ver[0] + '.' + ver[1] + '.' + ver[2] + '.' + ver[3];
      installs[sid]["rdbms_patchlevel"] = rdbms_patchlevel;

      ojvm_patchlevel = get_kb_item("Oracle/"+port+"/"+sid+"/OJVM Patch Level");
      if (!empty_or_null(ojvm_patchlevel))
        installs[sid]["ojvm_patchlevel"] = ojvm_patchlevel;
    }
  }
  # If that fails, check the local info
  else if (get_kb_item("Oracle/Patches/local"))
  {
    source = "  Ohome                : ";
    osandport = get_oracledb_host_os_and_port();
    os = osandport['os'];
    port = osandport['port'];

    res = get_kb_list("Oracle/*/RDBMS Patch Level");
    foreach ohome (keys(res))
    {
      rdbms_patchlevel = res[ohome];
      ohome = ohome - "Oracle/";
      ohome = ohome - "/RDBMS Patch Level";
      installs[ohome]["rdbms_patchlevel"] = rdbms_patchlevel;

      ver = split(rdbms_patchlevel, sep:'.', keep:FALSE);
      installs[ohome]["version"] = ver[0] + "." + ver[1] + "." + ver[2] + "." + ver[3];

      ojvm_patchlevel = get_kb_item("Oracle/"+ohome+"/OJVM Patch Level");
      if (!empty_or_null(ojvm_patchlevel))
        installs[ohome]["ojvm_patchlevel"] = ojvm_patchlevel;
    }
  }
  else
  {
    exit(1, "No Databases detected on the remote host.");
  }
  if (empty_or_null(os)) exit(1, "Failed to determine the host OS");
  if (empty_or_null(installs)) audit(AUDIT_NOT_INST, "Oracle Database");

  vuln = 0;
  foreach install (keys(installs))
  {
    vuln++;
    missing = '';
    dbversion = installs[install]["version"];
    # First check for the DB Patch
    if (!empty_or_null(patches[dbversion]['db']))
    {
      if (empty_or_null(patches[dbversion]['db'][os]) && os =~ "(aix|hpux|linux|solaris)$")
        os = 'nix';
      if (empty_or_null(patches[dbversion]['db'][os]) && os =~ "win(32|64)")
        os = 'win';
      if (!empty_or_null(patches[dbversion]['db'][os]))
      {
        fixpatchlevel = patches[dbversion]['db'][os]["patch_level"];
        if (ver_compare(ver:installs[install]["rdbms_patchlevel"], fix:fixpatchlevel, strict:FALSE) < 0)
        {
          missing += '\n  Missing DB Patches   : ' + patches[dbversion]['db'][os]['CPU'];
        }
      }
    }
    # Now check the OJVM
    if ('win' >!< os) os = 'nix';
    else os = 'win';
    if (!empty_or_null(patches[dbversion]["ojvm"][os]))
    {
      fixpatchlevel = patches[dbversion]["ojvm"][os]["patch_level"];
      if (ver_compare(ver:installs[install]["ojvm_patchlevel"], fix:fixpatchlevel, strict:FALSE) < 0)
        missing += '\n  Missing OJVM Patches : ' +  patches[dbversion]['ojvm'][os]['CPU'];
    }

    if (missing)
    {
      report = report +
        '\n' + source + install + missing;
    }
  }

  if (!empty_or_null(report))
  {
    if (vuln > 1) s = 's of Oracle Database are';
    else s = ' of Oracle Database is';

    if (report_verbosity > 0)
    {
      report =
        '\n' +
        'The following vulnerable instance'+s+' installed on the\n' +
        'remote host :\n' +
        report +
        '\n';

      if (!low_risk && !high_risk)
        security_warning(port:port, extra:report);
      else
      {
        if (low_risk)
          security_note(port:port, extra:report);
        else
          security_hole(port:port, extra:report);
      }
    }
    else
    {
      if (!low_risk && !high_risk)
        security_warning(port:port);
      else
      {
        if (low_risk)
          security_note(port:port);
        else
          security_hole(port:port);
      }
    }
  }
}

###
# Function to check if the patch has been applied.
# @param product The product name
# @param installs [Array] of product installs
# @param patches [Array] of patches for product versions
# @param kbprefix [String] the prefix for the KB for trimming
##
function oracle_product_check_vuln(product, installs, patches, kbprefix, low_risk, high_risk)
{
  local_var vuln, path, patched, version;
  local_var patch, patchesinstalled;
  local_var res, report, item, s1, s2;
  local_var notvuln;
  if (isnull(installs) || isnull(patches)) return NULL;

  vuln = 0;
  report = "";
  notvuln = make_array();
  foreach path (keys(installs))
  {
    version = installs[path];
    version = ereg_replace(pattern:'^([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+).*', string:version, replace:"\1");
    
    # Trim the KB data
    if (kbprefix)
    {
      path = path - kbprefix;
      path = path - '/Version';
    }

    if (!patches[version])
    {
      notvuln[path] = version;
      continue;
    }

    patched = FALSE;
    foreach patch (patches[version])
    {
      # First grab the patch IDs installed in the Oracle home
      patchesinstalled = query_scratchpad("SELECT patchid FROM oracle_patches WHERE ohome=?;", path);
      if (patchesinstalled)
      {
        foreach item (patchesinstalled)
        {
          if (item['patchid'] == patch)
          {
            patched = TRUE;
            break;
          }
          res = query_scratchpad("SELECT bugid FROM oracle_bugsfixed WHERE patchid=? AND bugid=?;", item['patchid'], patch);
          if (res)
          {
            patched = TRUE;
            break;
          }
        }
        if (patched) break;
      }
    }
    if (!patched)
    {
      vuln++;
      report +=
        '\n  Path           : ' + path +
        '\n  Version        : ' + version + 
        '\n  Required patch : ' + join(sep:' or ', patches[version]) + '\n';
    }
    else
      notvuln[path] = version;
  }
  if (report)
  {
    if (vuln > 1)
    {
      s1 = 's ';
      s2 = ' were found';
    }
    else
    {
      s1 = ' ';
      s2 = ' was found';
    }

    report =
      '\nThe following vulnerable version' + s1 + 'of ' + product + s2 +
      '\non the remote host : ' +
      report +
      '\n';
    
    if (report_verbosity > 0)
    {
      if (!low_risk && !high_risk)
        security_warning(port:0, extra:report);
      else
      {
        if (low_risk)
          security_note(port:0, extra:report);
        else 
          security_hole(port:0, extra:report);
      }
    }
    else
    {
      if (!low_risk && !high_risk)
        security_warning(0);
      else
      {
        if (low_risk)
          security_note(0);
        else
          security_note(0);
      }
    }
    exit(0);
  }
  if (max_index(keys(notvuln)) > 0)
  {
    # Provide a useful audit trail
    if (max_index(keys(notvuln)) > 1)
    {
      s1 = 's ';
      s2 = 'are';
    }
    else
    {
      s1 = ' ';
      s2 = 'is';
    }
    report = 
      '\nThe following instance' + s1 + 'of ' + product +
      '\n' + s2 + ' not affected : \n';
    foreach path (keys(notvuln))
    {
      report +=
        '\n  ' + path + ' : ' + notvuln[path];
    }
    report += '\n';
    exit(0, report);
  }
  # We should never get here
  exit(1, 'Unexpected error.\n');
}

# This function is only meant for finding subcomponents.  Top-level
# components should have a detection plugin
#
# @param ohome The oracle home to check
# @param compid The component to look for 
# @return ret The detected version 
#         NULL if the component is not found
##
function find_oracle_component_in_ohome(ohome, compid)
{
  local_var ret, res;
  local_var components, component, version;

  components = query_scratchpad("SELECT version, comp_name FROM oracle_products WHERE ohome=? AND comp_id=?;", ohome, compid);
  if (components)
  {
    foreach component (components)
    {   
      version = component['version'];
      return version;
    }   
  }
  return NULL;
}

##
# Finds patches for a particular Oracle Home
#
# @param ohomes A list of Oracle homes
# @return ret [Array] An array of applied patches
##
function find_patches_in_ohomes(ohomes)
{
  local_var ohome, bugids, bug, bugsfixed;
  local_var patch, patches, patchid, patched;
  local_var ret;

  patched = FALSE;
  ret = make_array();
  if (isnull(ohomes)) return -1;

  foreach ohome (ohomes)
  {
    ret[ohome] = make_array();
    bugids = make_list();
    patches = query_scratchpad("SELECT patchid, uniqid, patchdesc FROM oracle_patches WHERE ohome=?;", ohome);
    if (patches)
    {
      patched = TRUE;
      foreach patch (patches)
      {
        patchid = patch['patchid'];
        bugsfixed = query_scratchpad("SELECT bugid FROM oracle_bugsfixed WHERE patchid=?;", patchid);
        if (bugsfixed)
        {
          foreach bug (bugsfixed)
            bugids = make_list(bugids, bug['bugid']);
        }
        ret[ohome][patchid]['uniqid'] = patch['uniqid'];
        ret[ohome][patchid]['patchdesc'] = patch['patchdesc'];
        ret[ohome][patchid]['bugs'] = bugids;
      }
    }
  }
  if (!patched)
    return NULL;
  return ret;
}
