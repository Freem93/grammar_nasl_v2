###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not 
# be used from within scripts released under another license without the 
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#
# This include is used for ColdFusion local checks on Windows.
#
# coldfusion_win.inc
#
# @include smb_func.inc used by check_cfide_hotfix()
#
# $Revision: 1.6 $
###

# from smb_header.inc, used by check_cfide_hotfix()
global_var GENERIC_READ, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING;

##
# Checks if a hotfix related to the CFIDE directory has been applied or not.
# This function assumes the caller has already connected via SMB using something
# like session_init() from smb_internals.inc
#
# Adobe doesn't give any guidance on how to detect whether or not these CFIDE
# hotfixes have been applied properly, this is something we need to figure out
# on our own.  It usually involves look at the previous security update, comparing
# it to the current one, and finding a relevant string that has changed or is new
# in the current hotfix.
#
# @remark This method alerts on the absence of a string in a file so it could result
#         in inaccurate results if not used properly or if its assumption (every
#         CFIDE hotfix adds new strings to existing files) is incorrect
#
# @anonparam instance    name of the instance to check
# @anonparam web_file    file to check (pathname relative to the web root)       
# @anonparam searchterm  term to look for in 'file' that indicates 'hotfix_file' has been applied
# @anonparam hotfix_file the filename (per Adobe's KB) of the hotfix that is missing. e.g., CFIDE-hf900-00007.zip
#
# @return relevant plugin output information if the instance is vulnerable,
#         NULL otherwise
##
function check_cfide_hotfix()
{
  local_var instance, web_file, searchterm, hotfix_file, webroot, path, share, info, bytes_to_read, bytes_read;
  local_var rc, fh, length, blob;
  instance = _FCT_ANON_ARGS[0];
  web_file = _FCT_ANON_ARGS[1];
  searchterm = _FCT_ANON_ARGS[2];
  hotfix_file = _FCT_ANON_ARGS[3];

  webroot = get_kb_item('SMB/coldfusion/' + instance + '/webroot');
  path = webroot + web_file;
  share = path[0] + '$';
  web_file = substr(path, 2);

  rc = NetUseAdd(login:kb_smb_login(), password:kb_smb_password(), domain:kb_smb_domain(), share:share);
  if (rc != 1)
  {
    NetUseDel(close:FALSE);
    return NULL;
  }

  fh = CreateFile(
    file:web_file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh))
  {
    NetUseDel(close:FALSE);
    return NULL;
  }

  length = GetFileSize(handle:fh);
  if (length > 1048576) length = 1048576;  # sanity check - no file should be bigger than 1 meg
  while (strlen(blob) < length)
  {
    bytes_to_read = length - strlen(blob);
    if (bytes_to_read > 4096) bytes_to_read = 4096;

    bytes_read = ReadFile(handle:fh, offset:strlen(blob), length:bytes_to_read);
    if (strlen(bytes_read) == 0)
    {
      CloseFile(handle:fh);
      NetUseDel();
      exit(1, 'Function ReadFile() failed on ' + path + '.');
    }
    blob += bytes_read;
  }

  CloseFile(handle:fh);
  NetUseDel(close:FALSE);

  if (searchterm >!< blob)
  {
    info =
      '\nWeb root : ' + webroot +
      '\nMissing web hotfix : ' + hotfix_file;
  }


  return info;
}

##
# Checks if the given cumulative hotfix is installed.
#
# This is meant to be used for ColdFusion 10 (where every update
# appears to be a CHF), but may be useful for other situations
#
# @anonparam instance   name of the instance to check
# @anonparam chf_fix    int version of the hotfix cumulative hotfix to check for. e.g. 2 for chf10000002.jar
#
# @return    relevant plugin output information if the instance is vulnerable,
#            NULL otherwise
##
function check_jar_chf()
{
  local_var instance, chf_fix, cf_ver, chfs, chf, hf_dir, type, padding, missing_chf, info;
  instance = _FCT_ANON_ARGS[0];
  chf_fix = _FCT_ANON_ARGS[1];
  
  cf_ver = get_kb_item('SMB/coldfusion/' + instance + '/version');
  if (isnull(cf_ver)) return NULL;

  # Check if the appropriate CHF (or any subsequent CHFs) are installed
  chfs = get_kb_list('SMB/coldfusion/' + instance + '/chf');
  foreach chf (chfs)
  {
    if (int(chf) >= chf_fix)
      return NULL;
  }

  # if not, format some information suitable for plugin output
  hf_dir = get_kb_item('SMB/coldfusion/' + instance + '/cfroot');
  type = get_kb_item('SMB/coldfusion/' + instance + '/type');
  if (type == 'Multiserver')
    hf_dir += '\\WEB-INF\\cfusion\\lib\\updates';
  else if (type == 'Server')
    hf_dir += '\\lib\\updates';

  cf_ver = str_replace(string:cf_ver, find:'.', replace:'');
  if (chf_fix < 10)
    padding = '000';
  else if (chf_fix < 100)
    padding = '00';
  else if (chf_fix < 1000)
    padding = '0';
  else
    padding = '';
  missing_chf = 'chf' + cf_ver + padding + chf_fix + '.jar';

  info =
    '\nUpdate directory : ' + hf_dir +
    '\nMissing cumulative hotfix : ' + missing_chf;

  return info;
}

##
# Checks if the jar hotfix level is up to date.  Also checks if jars that Adobe
# states must be deleted are still present
#
# @anonparam instance   name of the instance to check
# @anonparam hf_fix     version of the hotfix level to check for. e.g. '00003' for hf900-00003.jar
# @anonparam chf_fix    the next (future) cumulative hotfix number, that presumably includes 'hf_fix'
# @anonparam delete_hf  a list of hotfix versions that must be deleted when applying 'hf_fix' (optional)
#
# @return    relevant plugin output information if the instance is vulnerable,
#            NULL otherwise
##
function check_jar_hotfix()
{
  local_var instance, cf_ver, ver, hf_dir, hf, chf, hf_fix, chf_fix, delete_hf, del_hf, type, jar, missing_hf, info;
  instance = _FCT_ANON_ARGS[0];
  hf_fix = _FCT_ANON_ARGS[1];
  chf_fix = _FCT_ANON_ARGS[2];
  delete_hf = _FCT_ANON_ARGS[3];

  cf_ver = get_kb_item('SMB/coldfusion/' + instance + '/version');
  if (isnull(cf_ver)) return NULL;

  if (isnull(delete_hf)) delete_hf = make_list();

  cf_ver = str_replace(string:cf_ver, find:'.', replace:'');
  hf = get_kb_list('SMB/coldfusion/' + instance + '/hf');
  chf = get_kb_list('SMB/coldfusion/' + instance + '/chf');
  missing_hf = 'hf' + cf_ver + '-' + hf_fix + '.jar';

  foreach ver (delete_hf)
    del_hf[ver] = TRUE;

  foreach ver (chf)
  {
    if (int(ver) >= chf_fix)
      return NULL;
  }

  foreach ver (hf)
  {
    # only compare zero padded hotfix numbers
    if (ver =~ '^000' && int(ver) >= int(hf_fix))
      missing_hf = NULL;

    # check to see if any of the HFs the advisory says to delete are still around
    if (del_hf[ver])
    {
      if (isnull(info))
        info += '\nHotfixes to delete :';

      info += ' hf' + cf_ver + '-' + ver + '.jar';
    }
  }

  # if the hotfix isn't missing, and they haven't forgotten to delete
  # any old hotfixes, this instance has been properly patched
  if (isnull(missing_hf) && isnull(info))
    return NULL;

  hf_dir = get_kb_item('SMB/coldfusion/' + instance + '/cfroot');
  type = get_kb_item('SMB/coldfusion/' + instance + '/type');
  if (type == 'Multiserver')
    hf_dir += '\\WEB-INF\\cfusion\\lib\\updates';
  else if (type == 'Server')
    hf_dir += '\\lib\\updates';

  if (isnull(missing_hf))
    missing_hf = 'None';

  info =
    '\nUpdate directory : ' + hf_dir +
    '\nMissing hotfix : ' + missing_hf +
    info;  # <- hotfixes to delete

  return info;
}

##
# Reads a list of ColdFusion instances found on the system from the KB
#
# @anonparam versions a list of versions to return. this lets a caller specify only instances of
#                     specific ColdFusion versionsu should be returned. this parameter is optional,
#                     and if it's not provided all instances will be returned
# @remark this function will exit if no instances were detected, or if no instances of 'versions' were found
#
# @return a hash of ColdFusion instance name => ColdFusion version number
##
function get_coldfusion_instances()
{
  local_var versions, instances, filter, ret, name, ver;
  versions = _FCT_ANON_ARGS[0];
  instances = get_kb_list_or_exit("SMB/coldfusion/instance");

  # filter out instances that aren't the desired version(s)
  ret = make_array();
  foreach name (instances)
  {
    ver = get_kb_item("SMB/coldfusion/" + name + "/version");

    # if the caller didn't specify only certain versions should be returned, return everything
    if (isnull(versions))
    {
      ret[name] = ver;
      continue;
    }

    # this could be more efficient but is good enough since it's not dealing with that much data
    foreach filter (versions)
    {
      if (ver == filter)
        ret[name] = ver;
    }
  }

  if (max_index(keys(ret)) == 0)
    exit(0, "None of the following versions of Adobe ColdFusion are installed: " + join(versions, sep:', '));

  return ret;
}
