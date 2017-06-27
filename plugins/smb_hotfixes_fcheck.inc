#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# smb_hotfixes_fcheck.inc
# $Revision: 1.78 $

HCF_CONNECT = -1; # Could not connect to port 139 or 445
HCF_NOAUTH =  -2; # No credentials or share does not exist
HCF_NOENT  =  -3; # File does not exist
HCF_ERR    =  -4; # Unknown error
HCF_NOVER  =  -5; # File version does not exist
HCF_NOTIME =  -6; # File timestamp does not exist.
HCF_PARSE  =  -7; # Unable to parse pathname.
HCF_OK     =   0; # No error
HCF_OLDER  =   1; # The remote file is older than what we wanted

HCF_UNACCESSIBLE_SHARE = 2;
HCF_ACCESSIBLE_SHARE   = 3;

global_var hcf_init;
global_var hcf_report;
global_var FILE_SHARE_READ, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING, GENERIC_READ;

# note, these value are altered only if smb_check_rollup() or
# smb_check_dotnet_rollup() are called, respectively
smb_check_rollup_done = TRUE;
smb_check_dotnet_rollup_done = TRUE;

hcf_report = NULL;
include("smb_fixes_summary.inc");

function hotfix_get_report()
{
  if (!smb_check_rollup_done || !smb_check_dotnet_rollup_done)
  {
    hcf_report += '\n\nNote that this result may be incomplete ' +
      'because the following were not enumerated successfully :';

    if (!smb_check_rollup_done)
      hcf_report += '\n  - Windows Monthly Rollups';
    if (!smb_check_dotnet_rollup_done)
      hcf_report += '\n  - .NET Framework Monthly Rollups';
  }
 return hcf_report;
}

function hotfix_get_audit_report()
{
  local_var out = 'affected.';
  if (!smb_check_rollup_done)
  {
    out += '\n\nNote that this result may be incomplete because ' +
      'rollups were not enumerated successfully.';
  }
  return out;
}

function hotfix_get_dotnet_audit_report(app, version)
{
  # audit(AUDIT_INST_VER_NOT_VULN, app, version);
  local_var out = app + ' version ' + version + ' is installed and ' +
    'not affected.';
  if (!smb_check_dotnet_rollup_done)
  {
    out += '\n\nNote that this result may be incomplete because ' +
      '.NET rollups were not enumerated successfully.';
  }
  return out;
}

function hotfix_add_report(bulletin, kb)
{
 if (
  defined_func("report_xml_tag") &&
  !isnull(bulletin) &&
  !isnull(kb)
 )
 {
	smb_hf_add(bulletin:bulletin, kb:kb);
	report_xml_tag(tag:bulletin, value:kb);
 }

 hcf_report += _FCT_ANON_ARGS[0];
}

function hotfix_security_hole()
{
 if ( ! isnull(hcf_report) )
  security_hole(port:get_kb_item("SMB/transport"), extra:'\n'+hotfix_get_report()+'\n');
 else
  security_hole(port:get_kb_item("SMB/transport"));
}

function hotfix_security_warning()
{
 if ( ! isnull(hcf_report) )
 security_warning(port:get_kb_item("SMB/transport"), extra:'\n'+hotfix_get_report()+'\n');
 else
 security_warning(port:get_kb_item("SMB/transport"));
}

function hotfix_security_note()
{
 if ( ! isnull(hcf_report) )
 security_note(port:get_kb_item("SMB/transport"), extra:'\n'+hotfix_get_report()+'\n');
 else
 security_note(port:get_kb_item("SMB/transport"));
}

function hotfix_check_fversion_init()
{
 local_var soc, port, name;

 #port = kb_smb_transport();
 #name = kb_smb_name();
 #soc = open_sock_tcp(port);
 #if  ( ! soc ) return HCF_CONNECT;

 #session_init(socket:soc, hostname:name);

 if(! smb_session_init()) return HCF_CONNECT;

 hcf_init = 1;
 return HCF_OK;
}

function hotfix_check_fversion_end()
{
 if ( hcf_init != 0 ) {
	NetUseDel();
	hcf_init = 0;
	}
 return HCF_OK;
}

##
# Checks if a file exists
#
# @param path absolute pathname of file to check
# @remark this function assumes hotfix_check_fversion_init() has already been called and succeeded
#
# @return TRUE  if the given file exists,
#         FALSE if the given file does not exist,
#         NULL  otherwise
##
function hotfix_file_exists(path)
{
  local_var version, exists;
  exists = NULL;

  version = hotfix_get_fversion(path:path);
  if (version['error'] == HCF_OK || version['error'] == HCF_NOVER)
    exists = TRUE;
  else if (version['error'] == HCF_NOENT)
    exists = FALSE;
  else
    exists = NULL;

  return exists;
}

##
# gets file contents
#
# @param path absolute pathname of file to read
# @remark this function assumes hotfix_check_fversion_init() has already been called and succeeded
#
# @return a hash 'ret' where
#         ret['error'] = error code (see HCF_ constants)
#         ret['data'] = file contents, if it could be obtained
##
function hotfix_get_file_contents(path)
{
  local_var match, share, file, login, pass, domain, r;
  local_var fh, size, offset, bytes_to_read, bytes_read, chunk, contents;

  # Accept argument anonymously.
  if (isnull(path)) path = _FCT_ANON_ARGS[0];

  if (isnull(path) || (strlen(path) == 0))
  {
    err_print('hotfix_get_file_contents(): missing required arg "path"');
    return make_array('error', HCF_ERR);
  }

  match = eregmatch(string:path, pattern:"^([A-Za-z]):(.+)$");
  if (isnull(match))
  {
    err_print('hotfix_get_fversion(): unable to parse pathname: ' + path);
    return make_array('error', HCF_PARSE);
  }

  share = match[1] + '$';
  file = match[2];

  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();

  if ( hcf_init == 0 ) hotfix_check_fversion_init();
  r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if ( r != 1 ) return make_array('error', HCF_NOAUTH);

  fh = CreateFile(
    file:file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh))
  {
    NetUseDel(close:FALSE);
    return make_array('error', HCF_NOENT);
  }

  size = GetFileSize(handle:fh);
  offset = 0;
  contents = '';

  while (offset < size)
  {
    if (size - offset < 16384)
      bytes_to_read = size - offset;
    else
      bytes_to_read = 16384;

    chunk = ReadFile(handle:fh, offset:offset, length:bytes_to_read);
    bytes_read = strlen(chunk);
    contents += chunk;
    offset += bytes_read;

    # bail out if the server did not send the number of bytes that were requested
    if (bytes_read != bytes_to_read)
    {
      CloseFile(handle:fh);
      NetUseDel(close:FALSE);
      return make_array('error', HCF_ERR);
      # never reached
    }
  }
  CloseFile(handle:fh);
  NetUseDel(close:FALSE);

  return make_array('error', HCF_OK, 'data', contents);
}

##
# gets a product version and saves it in the KB
#
# @param path absolute pathname of file to get product version for
#
# @return a hash 'ret' where
#         ret['error'] = error code (see HCF_ constants)
#         ret['value'] = product version, if one could be obtained
#
##
function hotfix_get_pversion(path)
{
  local_var match, share, file, login, pass, domain, r, fh, str_v, v, v2, kb_name, ret;

  if (isnull(path) || (strlen(path) == 0))
  {
    err_print('hotfix_get_pversion(): missing required arg "path"');
    return make_array('error', HCF_ERR);
  }

  match = eregmatch(string:path, pattern:"^([A-Za-z]):(.+)$");
  if (isnull(match))
  {
    err_print('hotfix_get_pversion(): unable to parse pathname: ' + path);
    return make_array('error', HCF_PARSE);
  }

  share = match[1] + '$';
  file = match[2];

  # Check if the product version is already in the KB
  kb_name = "SMB/ProductVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
  str_v = get_kb_item(kb_name);
  if (!isnull(str_v))
  {
    return make_array('error', HCF_OK, 'value', str_v);
    # never reached
  }

  # if not, connect to the target and get the product version
  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();

  if ( hcf_init == 0 ) hotfix_check_fversion_init();
  r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if ( r != 1 ) return make_array('error', HCF_NOAUTH);

  fh = CreateFile(
    file:file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh))
  {
    NetUseDel(close:FALSE);
    return make_array('error', HCF_NOENT);
  }

  v = GetProductVersion(handle:fh);
  CloseFile(handle:fh);
  NetUseDel(close:FALSE);

  if (!isnull(v))
    set_kb_item(name:kb_name, value:v);
  else
    return make_array('error', HCF_NOVER);

  return make_array('error', HCF_OK, 'value', v);
}

##
# gets a product name and saves it in the KB
#
# @param path absolute pathname of file to get product name for
#
# @return a hash 'ret' where
#         ret['error'] = error code (see HCF_ constants)
#         ret['value'] = product version, if one could be obtained
#
##
function hotfix_get_pname(path)
{
  local_var match, share, file, login, pass, domain, r, fh, str_v, v, v2, kb_name, ret;

  if (isnull(path) || (strlen(path) == 0))
  {
    err_print('hotfix_get_pname(): missing required arg "path"');
    return make_array('error', HCF_ERR);
  }

  match = eregmatch(string:path, pattern:"^([A-Za-z]):(.+)$");
  if (isnull(match))
  {
    err_print('hotfix_get_pname(): unable to parse pathname: ' + path);
    return make_array('error', HCF_PARSE);
  }

  share = match[1] + '$';
  file = match[2];

  # Check if the product name is already in the KB
  kb_name = "SMB/ProductNames/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
  str_v = get_kb_item(kb_name);
  if (!isnull(str_v))
  {
    return make_array('error', HCF_OK, 'value', str_v);
    # never reached
  }

  # if not, connect to the target and get the product version
  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();

  if ( hcf_init == 0 ) hotfix_check_fversion_init();
  r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if ( r != 1 ) return make_array('error', HCF_NOAUTH);

  fh = CreateFile(
    file:file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh))
  {
    NetUseDel(close:FALSE);
    return make_array('error', HCF_NOENT);
  }

  v = GetProductName(handle:fh);
  CloseFile(handle:fh);
  NetUseDel(close:FALSE);

  if (!isnull(v))
    set_kb_item(name:kb_name, value:v);
  else
    return make_array('error', HCF_NOVER);

  return make_array('error', HCF_OK, 'value', v);
}

##
# gets a file version and saves it in the KB
#
# @param path absolute pathname of file to get version for
# @remark this function assumes hotfix_check_fversion_init() has already been called and succeeded
#
# @return a hash 'ret' where
#         ret['error'] = error code (see HCF_ constants)
#         ret['value'] = file version, if one could be obtained
##
function hotfix_get_fversion(path)
{
  local_var match, share, file, login, pass, domain, r, fh, str_v, v, v2, kb_name, ret;

  if (isnull(path) || (strlen(path) == 0))
  {
    err_print('hotfix_get_fversion(): missing required arg "path"');
    return make_array('error', HCF_ERR);
  }

  match = eregmatch(string:path, pattern:"^([A-Za-z]):(.+)$");
  if (isnull(match))
  {
    err_print('hotfix_get_fversion(): unable to parse pathname: ' + path);
    return make_array('error', HCF_PARSE);
  }

  share = match[1] + '$';
  file = match[2];

  # Check if the file version is already in the KB
  kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
  str_v = get_kb_item(kb_name);
  if (!isnull(str_v))
  {
    v2 = split( str_v, sep:'.', keep:0);
    v = make_list(v2[0], v2[1], v2[2], v2[3]);
    return make_array('error', HCF_OK, 'value', v);
    # never reached
  }

  # if not, connect to the target and get the file version
  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();

  if ( hcf_init == 0 ) hotfix_check_fversion_init();
  r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if ( r != 1 ) return make_array('error', HCF_NOAUTH);

  fh = CreateFile(
    file:file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh))
  {
    NetUseDel(close:FALSE);
    return make_array('error', HCF_NOENT);
  }

  v = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
  NetUseDel(close:FALSE);

  if (!isnull(v))
    set_kb_item(name:kb_name, value:strcat(v[0], '.', v[1], '.', v[2], '.', v[3]));
  else
    return make_array('error', HCF_NOVER);

  return make_array('error', HCF_OK, 'value', v);
}

##
# gets a file timestamp and saves it in the KB
#
# @param path absolute pathname of file to get product version for
#
# @return a hash 'ret' where
#         ret['error'] = error code (see HCF_ constants)
#         ret['value'] = timestamp, if one could be obtained
#
##
function hotfix_get_timestamp(path)
{
  local_var match, share, file, login, pass, domain, r, fh, str_v, v, v2, kb_name, ret;

  if (isnull(path) || (strlen(path) == 0))
  {
    err_print('hotfix_get_timestamp(): missing required arg "path"');
    return make_array('error', HCF_ERR);
  }

  match = eregmatch(string:path, pattern:"^([A-Za-z]):(.+)$");
  if (isnull(match))
  {
    err_print('hotfix_get_timestamp(): unable to parse pathname: ' + path);
    return make_array('error', HCF_PARSE);
  }

  share = match[1] + '$';
  file = match[2];

  # Check if the product version is already in the KB
  kb_name = "SMB/Timestamps/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
  str_v = get_kb_item(kb_name);
  if (!isnull(str_v))
  {
    v2 = split( str_v, sep:'.', keep:0);
    v = make_list(v2[0], v2[1], v2[2], v2[3]);
    return make_array('error', HCF_OK, 'value', v);
    # never reached
  }

  # if not, connect to the target and get the product version
  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();

  if ( hcf_init == 0 ) hotfix_check_fversion_init();
  r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if ( r != 1 ) return make_array('error', HCF_NOAUTH);

  fh = CreateFile(
    file:file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh))
  {
    NetUseDel(close:FALSE);
    return make_array('error', HCF_NOENT);
  }

  ret = GetFileVersionEx(handle:fh);
  CloseFile(handle:fh);
  NetUseDel(close:FALSE);

  if (!isnull(ret) && !isnull(ret["dwTimeDateStamp"]))
    set_kb_item(name:kb_name, value:ret["dwTimeDateStamp"]);
  else
    return make_array('error', HCF_NOTIME);

  return make_array('error', HCF_OK, 'value', ret["dwTimeDateStamp"]);
}

##
# Checks if the given file version is older than 'version'
#
# @param file filename of the binary to check
# @param fversion specifies a value to compare "version" to, instead of reading the version from the file (optional)
# @param version version to compare to
# @param path absolute path (including drive letter) of the directory containing "file"
# @param min_version a minimum cutoff 'version'. If 'version' is lower than this value, no check is performed (optional)
# @param bulletin Microsoft bulletin ID in the MSyy-xyz format
# @param kb Microsoft KB number (number only)
# @param product name of the product that "file" is a part of (optional)
# @param channel name of the Office 2016 Click-to-Run update channel e.g. 'Deferred' (optional)
# @param channel_version version number of the Office 2016 Click-to-Run channel e.g. '1509' (optional)
# @param channel_product name of the Office 2016 Click-to-Run product e.g. 'Word' (required if channel or channel_version is present)
# @param rollup_check used to format report output for smb_check_rollup.nasl
# Optional parm and should contain rollup date (ie 12_2016) when set
##
function hotfix_check_fversion(file, fversion, version, path, min_version, bulletin, kb, product, channel, channel_version, channel_product, rollup_check)
{
  local_var login, pass, domain, share, r, handle, v, str_v,v2, i, kb_name, backslash, report, kb_channel, kb_channels, kb_channel_version, matched_channel, kb_channel_versions, matched_channel_version;

 if ( hcf_init == 0 )
	{
		if ( hotfix_check_fversion_init() != HCF_OK ) return 0;
	}


  if (isnull(path) || (strlen(path) == 0))
    path = hotfix_get_systemroot();

  if ( isnull(path) ) return HCF_ERR;

  # Return HCF_OK if the check is for a different channel or channel_version
  if (channel)
  {
    if (!channel_product) return HCF_ERR; # channel was sent without channel_product
    if (tolower(channel_product) == "office") kb_channels = get_kb_list("SMB/Office/16.0/Channel");
    else kb_channels = get_kb_list("SMB/Office/"+channel_product+"/16.0/Channel");
    matched_channel = FALSE;
    foreach kb_channel (kb_channels)
    {
      if (empty_or_null(kb_channel))
        continue; # Product not found or doesn't have a Channel set
      if (tolower(kb_channel) == tolower(channel))
      {
        matched_channel = TRUE;
        break;
      }
    }
    if (!matched_channel) return HCF_OK;
  }
  if (channel_version)
  {
    if (!channel_product) return HCF_ERR; # channel_version was sent without channel_product
    if (tolower(channel_product) == "office") kb_channel_versions = get_kb_list("SMB/Office/16.0/ChannelVersion");
    else kb_channel_versions = get_kb_list("SMB/Office/"+channel_product+"/16.0/ChannelVersion");
    matched_channel_version = FALSE;
    foreach kb_channel_version (kb_channel_versions)
    {
      if (empty_or_null(kb_channel_version))
        continue; # Product not found or doesn't have a Channel set
      if (kb_channel_version == channel_version)
      {
        matched_channel_version = TRUE;
        break;
      }
    }
    if (!matched_channel_version) return HCF_OK;
  }

 share = ereg_replace(pattern:"^([A-Za-z]):.*", string:path, replace:"\1$");
 if ( file[0] == "\" || ( strlen(path) > 0 && path [ strlen(path) - 1 ] == "\") )
      backslash = "";
 else
      backslash = "\";

 file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1" + backslash + file);

 # Get the file version
 if ( !isnull(fversion))
 {
   v2 = split(fversion, sep:'.', keep:FALSE);
   v = make_list(v2[0], v2[1], v2[2], v2[3]);
 }
 else
 {
   kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
   str_v = get_kb_item(kb_name);
   if ( ! isnull(str_v) )
   {
    v2 = split( str_v, sep:'.', keep:0);
    v = make_list(v2[0], v2[1], v2[2], v2[3]);
   }
 }
 if (isnull(v))
 {
  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();

  r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if ( r != 1 ) return HCF_NOAUTH;

  handle = CreateFile(file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
  if ( isnull(handle) ) return HCF_NOENT;

  v = GetFileVersion(handle:handle);
  CloseFile(handle:handle);
  if ( ! isnull(v) )
    set_kb_item(name:kb_name, value:v[0] + "." + v[1] + "." + v[2] + "." + v[3]);
  else return HCF_NOVER;
 }

 if ( int(v[0]) == 0 && int(v[1]) == 0 && int(v[2]) == 0 && int(v[3]) == 0 ) return HCF_NOVER;

 if ( !isnull(min_version) )
 {
  min_version = split(min_version, sep:'.', keep:0);
  min_version = make_list(int(min_version[0]), int(min_version[1]), int(min_version[2]), int(min_version[3]));

  for ( i = 0; i < max_index(v) ; i ++ )
  {
   if ( (v[i] < min_version[i]) ) return HCF_OK;
   else if (v[i] > min_version[i])  break;
  }
 }

 version = split(version, sep:'.', keep:0);
 version = make_list(int(version[0]), int(version[1]), int(version[2]), int(version[3]));

 for ( i = 0; i < max_index(version) ; i ++ )
 {
  if ( (v[i] < version[i]) )
  {
    if (product)
      report = '\n  Product : ' + product + '\n';
    else
      report = '\n';

    if (!isnull(rollup_check))
      report += rollup_check;
    report +=
      '  - ' + (share - '$') + ':' + file + ' has not been patched.\n' +
      '    Remote version : ' + v[0] + '.' + v[1] + '.' + v[2] + '.' + v[3] + '\n' +
      '    Should be      : ' + version[0] + '.' + version[1] + '.' + version[2] + '.' + version[3] + '\n';
    hotfix_add_report(
      report,
      bulletin:bulletin,
      kb:kb
    );
    return HCF_OLDER;
  }
  else if (v[i] > version[i]) return HCF_OK;
 }

 return HCF_OK;
}

function hotfix_is_vulnerable(os, sp, arch, os_build, file, version, dir, path, min_version, bulletin, kb, product, channel, channel_product, channel_version)
{
 local_var r;
 local_var my_sp, my_os, my_arch, my_os_build;


 my_os = get_kb_item("SMB/WindowsVersion");
 my_sp = get_kb_item("SMB/CSDVersion");
 my_arch = get_kb_item("SMB/ARCH");
 my_os_build = get_kb_item("SMB/WindowsVersionBuild");
 if ( my_sp )
 {
  my_sp = ereg_replace(pattern:".*Service Pack ([0-9]).*", string:my_sp, replace:"\1");
  my_sp = int(my_sp);
 }
 else my_sp = 0;

 if ( os >!< my_os ) return 0;
 if ( ! isnull(sp) && my_sp != sp ) return 0;
 if ( ! isnull(arch) && my_arch != arch ) return 0;
 if ( ! isnull(os_build) && my_os_build != os_build ) return 0;

 r = hotfix_check_fversion(file:dir + "\" + file, version:version, path:path, min_version:min_version, bulletin:bulletin, kb:kb, product:product, channel:channel, channel_product:channel_product, channel_version:channel_version);
 if ( r == HCF_OLDER)
 {
	smb_hf_add(os:os, sp:sp, file:file, version:version, bulletin:bulletin, kb:kb);
	return 1;
 }
 else
	return 0;
}

##
# Checks if the host has the given rollup applied
#
# @param os os version that is being checked
# @param sp sp of the host that is being checked
# @param os_build edition of windows 10 to be checked
# @param rollup_date MM_YYYY formatted string of the PT rollup
# @param bulletin bulletin to include in the report output
# @param rollup_kb_list list of kbs related to the monthly rollup
# @param arch architecture to check against
# @return
#   TRUE if vulnerable (rollup not applied)
#   FALSE if rollup is applied or host is not applicable (ex: wrong os)
##
function smb_check_rollup(os, sp, os_build, rollup_date, bulletin, rollup_kb_list, arch)
{
  local_var host_rollup, h_month, h_year;
  local_var new_rollup, n_month, n_year;
  local_var my_sp, my_os, my_arch, my_os_build;
  local_var kb, report, file_report;

  # Verify host constraints
  my_os = get_kb_item("SMB/WindowsVersion");
  my_sp = get_kb_item("SMB/CSDVersion");
  my_arch = get_kb_item("SMB/ARCH");
  my_os_build = get_kb_item("SMB/WindowsVersionBuild");
  if ( my_sp )
  {
    my_sp = ereg_replace(pattern:".*Service Pack ([0-9]).*", string:my_sp, replace:"\1");
    my_sp = int(my_sp);
  }
  else my_sp = 0;

  if ( os >!< my_os ) return FALSE;
  if ( !isnull(sp) && my_sp != sp ) return FALSE;
  if ( !isnull(arch) && my_arch != arch ) return FALSE;
  if ( !isnull(os_build) && my_os_build != os_build ) return FALSE;

  # Ensure rollups were enumerated successfully
  smb_check_rollup_done = get_kb_item("smb_check_rollup/done");
  if (!smb_check_rollup_done) return FALSE;

  # Check for oneoff update
  if(get_kb_item("smb_rollup/" + rollup_date) == 1) return FALSE;

  # Get the latest cumulative rollup for the host
  host_rollup = get_kb_item('smb_rollup/latest');

  # If none, host does not have a cumulative rollup applied
  if (isnull(host_rollup) || host_rollup == 'none')
  {
    report = 'The remote host is missing one of the following rollup KBs : ';
    foreach kb (rollup_kb_list)
    {
      report += '\n  - ' + kb;
      hotfix_add_report(report, bulletin:bulletin, kb:kb);
      report = '';
    }

    file_report = get_kb_item("smb_rollup/version_report/"+rollup_date);
    if (!empty_or_null(file_report))
      hcf_report += '\n\n'+ file_report;

    return TRUE;
  }

  host_rollup = split(host_rollup, sep:'_');
  h_month = int(host_rollup[0]);
  h_year = int(host_rollup[1]);

  new_rollup = split(rollup_date, sep:'_');
  n_month = int(new_rollup[0]);
  n_year = int(new_rollup[1]);

  # Determine if host rollup >= supplied rollup
  if (h_year > n_year || (h_year == n_year && h_month >= n_month)) return FALSE;
  else if (h_year < n_year || (h_year == n_year && h_month < n_month))
  {
    report = 'The remote host is missing one of the following rollup KBs : ';
    foreach kb (rollup_kb_list)
    {
      report += '\n  - ' + kb;
      hotfix_add_report(report, bulletin:bulletin, kb:kb);
      report = '';
    }
    file_report = get_kb_item("smb_rollup/version_report/" +rollup_date);

    if (!empty_or_null(file_report))
      hcf_report += '\n\n'+ file_report;

    hotfix_add_report(report, bulletin:bulletin, kb:kb);
    return TRUE;
  }
}

function smb_check_dotnet_rollup(rollup_date, dotnet_ver)
{
  local_var kb_base = "smb_dotnet_rollup/"+rollup_date+"/"+dotnet_ver+"/not_inst/*";
  local_var not_inst = get_kb_list(kb_base);

  local_var bulletin, bulletin_yr, bulletin_mo;
  local_var report, file_report, kb;

  bulletin = split(rollup_date, sep:'_', keep:FALSE);
  bulletin_mo = bulletin[0];
  bulletin_yr = bulletin[1];
  if (strlen(bulletin_yr) == 4) bulletin_yr = substr(bulletin_yr, 2);

  smb_check_dotnet_rollup_done = get_kb_item("smb_check_dotnet_rollup/done");
  if (!smb_check_dotnet_rollup_done) return FALSE;

  local_var host_rollup = get_kb_item('smb_dotnet_rollup/'+dotnet_ver+'/latest');

  if (empty_or_null(not_inst)) return FALSE;

  if (isnull(host_rollup) || host_rollup == 'none')
  {
    report = 'Microsoft .NET Framework ' + dotnet_ver + '\n';
    report += 'The remote host is missing one of the following rollup KBs : ';
    foreach kb (not_inst)
    {
      report += '\n  - ' + kb;
      # e.g. MS17-04
      bulletin = 'MS'+bulletin_yr+'-'+bulletin_mo;
      hotfix_add_report(report, bulletin:bulletin, kb:kb);
      #  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
      replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
      report = '';
    }
    file_report = get_kb_item("smb_dotnet_rollup/version_report/"+rollup_date+"/"+dotnet_ver);
    if (!empty_or_null(file_report))
      hcf_report += '\n\n'+ file_report;
    hotfix_add_report(report, bulletin:bulletin, kb:kb);
    return TRUE;
  }
  host_rollup = split(host_rollup, sep:'_');
  local_var h_month = int(host_rollup[0]);
  local_var h_year = int(host_rollup[1]);
  local_var new_rollup = split(rollup_date, sep:'_');
  local_var n_month = int(new_rollup[0]);
  local_var n_year = int(new_rollup[1]);

  # Determine if host rollup >= supplied rollup
  if (h_year > n_year || (h_year == n_year && h_month >= n_month)) return FALSE;
  if (h_year < n_year || (h_year == n_year && h_month < n_month))
  {
    report = 'Microsoft .NET Framework ' + dotnet_ver + '\n';
    report += 'The remote host is missing one of the following rollup KBs : ';
    foreach kb (not_inst)
    {
      report += '\n  - ' + kb;
      bulletin = 'MS'+bulletin_yr+'-'+bulletin_mo;
      hotfix_add_report(report, bulletin:bulletin, kb:kb);
      replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
      report = '';
    }

    file_report = get_kb_item("smb_dotnet_rollup/version_report/"+rollup_date+"/"+dotnet_ver);
    if (!empty_or_null(file_report))
      hcf_report += '\n\n'+ file_report;
    hotfix_add_report(report, bulletin:bulletin, kb:kb);
    return TRUE;
  }

  return FALSE;
}

##
# Checks the version of an Office Product
#
# @param product The product to check
# @param display_name An optional display name to use for reporting
# @param checks An array of checks to perform
# @param bulletin The bulletin that is being checked
#
# @return TRUE if the host is vulnerable
#         FALSE if the host is not affected
#         NULL otherwise
##

function hotfix_check_office_product(product, display_name, checks, bulletin)
{
  local_var office_ver_mapping, spmatch, info, vuln, disp_product;
  local_var check, install, version, ver, i, installs, path, sp, channel, channel_version;
  vuln = FALSE;

  office_ver_mapping = make_array(
    "8.0", "97",
    "9.0", "2000",
    "10.0", "XP",
    "11.0", "2003",
    "12.0", "2007",
    "14.0", "2010",
    "15.0", "2013",
    "16.0", "2016"
  );
  if (isnull(product)) return NULL;
  if (isnull(checks)) return NULL;
  if (isnull(bulletin)) return NULL;

  installs = get_kb_list("SMB/Office/"+product+"/*/ProductPath");
  if (!isnull(installs))
  {
    foreach install (keys(installs))
    {
      info = '';
      version = install - ('SMB/Office/'+product + "/");
      version = version - '/ProductPath';
      path = installs[install];

      ver = split(version, sep:'.', keep:FALSE);
      ver = ver[0] + '.' + ver[1];
      if (checks[ver])
      {
        # If there is only one check, convert it to a nested list
        # so we are always looping over a list.
        if (!is_list(checks[ver]))
        {
          checks[ver] = make_nested_list(checks[ver]);
        }
        if (ver == "16.0") channel = get_kb_item("SMB/Office/"+product+"/16.0/Channel");
        if (ver == "16.0") channel_version = get_kb_item("SMB/Office/"+product+"/16.0/ChannelVersion");
        foreach check (checks[ver])
        {
          if (check["min_ver"] && (ver_compare(ver:version, fix:check["min_ver"]) < 0))
            continue;

          # If a channel or channel_version is included in the check, the target product channel or channel_version must exist and match
          if (check["channel"] && (empty_or_null(channel) || (tolower(channel) != tolower(check["channel"]))))
            continue;
          if (check["channel_version"] && (empty_or_null(channel_version) || (tolower(channel_version) != tolower(check["channel_version"]))))
            continue;

          if (office_ver_mapping[ver])
          {
            sp = get_kb_item('SMB/Office/'+office_ver_mapping[ver]+'/SP');
          }
          else return FALSE;
          # Check if the Office SP is the expected SP
          if (!isnull(check["sp"]))
          {
            if (typeof(check["sp"]) == "array" && is_list(check["sp"]))
            {
              for (i=0; i < max_index(check["sp"]); i++)
              {
                if (int(sp) == int(check["sp"][i]))
                {
                  spmatch = TRUE;
                  break;
                }
              }
            }
            else
            {
              if (int(sp) == int(check["sp"]))
                spmatch = TRUE;
            }
          }
          else
            spmatch = TRUE;
          if (spmatch && (ver_compare(ver:version, fix:check["version"]) < 0))
          {
            if (isnull(display_name))
              info =  '\n  Product           : ' + product + " " + office_ver_mapping[ver];
            else
              info =  '\n  Product           : ' + display_name + " " +office_ver_mapping[ver];
            
            info +=
              '\n  - ' + path + " has not been patched." +
              '\n    Remote version    : ' + version +
              '\n    Fixed version     : ' + check["version"] + '\n';
            vuln = TRUE;
            hotfix_add_report(info, bulletin:bulletin, kb:check[ver]["kb"]);
          }
        }
      }
    }
  }
  return vuln;
}

function is_accessible_share(share)
{
 local_var login, pass, domain, r;

 if (isnull(share))
 {
  share = hotfix_get_systemroot();
  if ( ! share ) return 0;
  share = ereg_replace(pattern:"^([A-Za-z]):.*", string:share, replace:"\1$");
 }

  r =  get_kb_item("SMB/AccessibleShare/" + share);
  if ( r == HCF_UNACCESSIBLE_SHARE ) return 0; # Not Accessible
  else if ( r == HCF_ACCESSIBLE_SHARE ) return 1;

  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();

  if ( hcf_init == 0 ) hotfix_check_fversion_init();
  r = NetUseAdd(login:login, password:pass, domain:domain, share:share);

  if ( r != 1 )
	{
	 hotfix_check_fversion_end();
	 r = HCF_UNACCESSIBLE_SHARE;
	}
  else
	{
  	 NetUseDel(close:FALSE);
	 r = HCF_ACCESSIBLE_SHARE;
	}

	replace_kb_item(name:"SMB/AccessibleShare/" + share, value:r);

  if (r == HCF_ACCESSIBLE_SHARE)
    return 1;
  else
    return 0;
}


function hotfix_path2share(path)
{
 return ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
}

##
# Handles errors from hotfix functions
#
# @param error_code Value of error code returned from hotfix function.
#
# @param file Required.  File path to the file you are checking.
#
# @param appname Optional.  If the checked file doesn't exist, this parameter
#                will allow audit() to be called with AUDIT_UNINST and the name
#                of the application.  Useful for installation detection plugins.
#
# @remark If checking more than one file in a loop, setting exit_on_fail
#
# @return If no error, the function returns NULL.  If there is an error,
#         the function will trigger an exit or return an error string
#         depending on type of error and the value of exit_on_fail
##
function hotfix_handle_error(error_code, file, appname, exit_on_fail)
{
  local_var fatal_error, match, share;

  # the fatal errors below should not happen unless there is a plugin bug
  fatal_error = '';
  if(isnull(error_code))
    fatal_error = 'missing \'error_code\' argument to handle_hotfix_error()';
  if(isnull(file))
    fatal_error = 'missing \'file\' argument to handle_hotfix_error()';

  if(fatal_error != '')
  {
    hotfix_check_fversion_end();
    exit(1, fatal_error);
  }

  # if everything is OK, don't return anything
  if(error_code == HCF_OK)
    return FALSE;

  if(isnull(exit_on_fail)) exit_on_fail = FALSE;

  if (error_code == HCF_PARSE)
  {
    if(!exit_on_fail)
      return 'Unable to parse pathname \'' + file + '\'.';
    else
    {
      hotfix_check_fversion_end();
      if(isnull(appname))
        exit(1, 'Unable to parse pathname \'' + file + '\'.');
      else
        audit(AUDIT_UNINST, appname);
    }
  }
  else if (error_code == HCF_NOENT)
  {
    if(!exit_on_fail)
      return 'The file \'' + file + '\' does not exist.';
    else
    {
      hotfix_check_fversion_end();
      if(isnull(appname))
        exit(1, 'The file \'' + file + '\' does not exist.');
      else
        audit(AUDIT_UNINST, appname);
    }
  }
  else if (error_code == HCF_CONNECT)
  {
    if(!exit_on_fail)
      return 'Error connecting to SMB service on remote host.';
    else
    {
      hotfix_check_fversion_end();
      exit(1, 'Error connecting to SMB service on remote host.');
    }
  }
  else if (error_code == HCF_UNACCESSIBLE_SHARE)
  {
    share = hotfix_path2share(path:file);
    if(!exit_on_fail)
      return 'Failed to connect to the \'' + share + '\' share.';
    else
    {
      hotfix_check_fversion_end();
      audit(AUDIT_SHARE_FAIL, share);
    }
  }
  else if (error_code == HCF_NOAUTH)
  {
    if(!exit_on_fail)
      return "Error accessing '" + file + "'. Invalid credentials or share doesn't exist.";
    else
    {
      hotfix_check_fversion_end();
      exit(1, "Error accessing '" + file + "'. Invalid credentials or share doesn't exist.");
    }
  }
  else if (error_code == HCF_NOVER)
  {
    if(!exit_on_fail)
      return 'Failed to get the file version of \'' + file + '\'.';
    else
    {
      hotfix_check_fversion_end();
      audit(AUDIT_VER_FAIL, file);
    }
  }
  else if (error_code == HCF_NOTIME)
  {
    if(!exit_on_fail)
      return 'Failed to get the timestamp of \'' + file + '\'.';
    else
    {
      hotfix_check_fversion_end();
      exit(1, "Failed to get the timestamp of '" + file + "'.");
    }
  }
  else
  {
    if(!exit_on_fail)
      return 'Unknown error when attempting to access \'' + file + '\'.';
    else
    {
      hotfix_check_fversion_end();
      exit(1, "Unknown error when attempting to access '" + file + "'.");
    }
  }
}

##
# Appends value to path properly separated by "/"
#
# @param path Path to append to
#
# @param value Value to append to path
#
# @return Appended path string
#
function hotfix_append_path(path, value)
{
  if(isnull(path) || path == '')
    exit(1, 'no path specified in hotfix_append_path()');
  if(isnull(value) || value == '')
    exit(1, 'no value specified in hotfix_append_path()');

  # force path to end with a \
  if(path[strlen(path) - 1] != "\")
    path = path + "\";

  # value shouldn't begin with \
  if (value[0] == "\")
    value = substr(value, 1);

  return path + value;
}

##
# WinSxS file checks
#
# @param dir WinSxS directory
# @param os Operating System
# @param files List of files to check
# @param versions List of vulnerable versions (LDR/GDR)
# @param max_versions List of max versions
# @param bulletin Bulletin that is being checked
# @param kb KB that is being checked
# @param key Registry in case we couldn't get all file versions
# @param session Existing SMB session values
# @return 1 if vulnerable
#         0 if not vulnerable
#         NULL if the function was called incorrectly
##
function hotfix_check_winsxs(dir, arch, files, os, sp, versions, max_versions, bulletin, kb, key, session)
{
  local_var patched, report, file, fname, vulnfile;
  local_var my_os, my_arch, my_sp;
  local_var rootfile, ver, i, winsxs;
  local_var highestver, lowestcutoff;
  local_var null_ver, r, handle, key_h;
  local_var login, pass, domain;

  rootfile = hotfix_get_systemroot();
  my_os = get_kb_item("SMB/WindowsVersion");
  my_sp = get_kb_item("SMB/CSDVersion");
  my_arch = get_kb_item("SMB/ARCH");
  if (my_sp)
  {
    my_sp = ereg_replace(pattern:".*Service Pack ([0-9]).*", string:my_sp, replace:"\1");
    my_sp = int(my_sp);
  }
  else my_sp = 0;

  if (os >!< my_os) return 0;
  if (!isnull(sp) && my_sp != sp) return 0;
  if (!isnull(arch) && my_arch != arch) return 0;

  if (max_index(max_versions) && (max_index(versions) != max_index(max_versions))) return 0;
  if (!isnull(files) && max_index(files) > 0)
  {
    patched = FALSE;
    highestver = '0.0.0.0';
    vulnfile = FALSE;
    null_ver = '';

    # When the patched DLL is added to the SxS dir, the older (vulnerable)
    # versions of the file remain in the SxS dir. This checks to see if there is
    # _any_ file that has been patched
    foreach file (files)
    {
      if (!fname) fname = ereg_replace(pattern:'^\\\\.*\\\\(.*)$', string:file, replace:"\1");

      ver = _winsxs_get_file_version(file);

      # We should always get a file version. If we don't we need to note it.
      if (isnull(ver))
      {
         null_ver += '  - ' + file + '\n';
         continue;
      }
      # Track the highest version installed so we can report on
      # it if the host is vulnerable
      if (ver_compare(ver:ver, fix:highestver) >= 0)
        highestver = ver;

      for (i=0; i < max_index(versions); i++)
      {
        # If an empty string is passed as the value for max_versions[i]
        # don't check the ceiling version
        if (isnull(max_versions) || !max_versions[i])
        {
          if (_winsxs_version_cmp(a:ver, b:versions[i]) >= 0)
          {
            patched = TRUE;
            break;
          }
          else vulnfile = TRUE;
        }
        else
        {
          if (_winsxs_version_cmp(a:ver, b:versions[i]) >= 0)
          {
            if (_winsxs_version_cmp(a:ver, b:max_versions[i]) < 0)
            {
              patched = TRUE;
              break;
            }
          }
          else
            vulnfile = TRUE;
        }
      }
    }

    # We want to check the registry for the KB if we got a null version
    # and we suspect the host may not be patched
    if(!empty(null_ver) && !patched)
    {
      if(isnull(key))
      {
        report =
        '\nNessus does not have a registry key to check for KB' + kb + '.\n' +
        '\nNessus did not find a version for the following files :\n' +
        null_ver;
        hotfix_add_report(report, bulletin:bulletin, kb:kb);
        return 1;
      }

      # Now we will need to open to the IPC share to check the registry
      login  = kb_smb_login();
      pass   = kb_smb_password();
      domain = kb_smb_domain();

      NetUseDel(close:FALSE); # close existing SMB share
      r = NetUseAdd(login:login, password:pass, domain:domain, share:'IPC$');
      local_var ret = NULL;
      if ( r != 1 )
      {
        report =
        '\nNessus was unable to connect to the $IPC share.\n' +
        '\nNessus did not find a version for the following files :\n' +
        null_ver;
        hotfix_add_report(report, bulletin:bulletin, kb:kb);
        ret = 1;
      }

      if (isnull(ret))
      {
        handle = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
        if(isnull(handle))
        {
          report =
          '\nNessus was unable to open a connection to the HKLM hive.\n' +
          '\nNessus did not find a version for the following files :\n' +
          null_ver;
          hotfix_add_report(report, bulletin:bulletin, kb:kb);
          ret = 1;
        }
      }

      if (isnull(ret))
      {
        key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
        if(isnull(key_h))
        {
          RegCloseKey(handle:key_h);
          RegCloseKey(handle:handle);
          report =
          '\nAccording to the registry, KB' + kb + ' is missing.\n' +
          '\nNessus did not find a version for the following files :\n' +
          null_ver;
          hotfix_add_report(report, bulletin:bulletin, kb:kb);
          ret = 1;
        }
        else
        {
          RegCloseKey(handle:key_h);
          RegCloseKey(handle:handle);
          ret = 0;
        }
      }

      if (!empty_or_null(session))
      {
        NetUseDel(close:FALSE); # close IPC$ share
        # restore existing SMB session
        NetUseAdd(
          login    : session['login'],
          password : session['password'],
          domain   : session['domain'],
          share    : session['share']
        );
      }

      if (!isnull(ret)) return ret;
    }

    if (vulnfile && !patched)
    {
      lowestcutoff = '0.0.0.0';
      # Determine the appropriate cutoff value
      for (i=0; i < max_index(versions); i++)
      {
        if (ver_compare(ver:highestver, fix:versions[i]) < 0 && ('0.0.0.0' >< lowestcutoff || ver_compare(ver:versions[i], fix:lowestcutoff) < 0))
        {
          lowestcutoff = versions[i];
        }
      }

      winsxs = rootfile + "\WinSxS";
      report =
        '\n' +
        'None of the versions of \''+fname+'\' under '+winsxs+'\n' +
        'have been patched.\n' +
        '  Fixed version : ' + lowestcutoff;
      hotfix_add_report(report, bulletin:bulletin, kb:kb);
      return 1;
    }
  }
  return 0;
}

##
# Lists directories or files in a directory
#
# @param basedir
# @param level
# @param dir_pat
# @param file_pat
#
# @return list of directories / files
##
function list_dir(basedir, level, dir_pat, file_pat, max_recurse, share)
{
  local_var contents, ret, subdirs, subsub;
  local_var login, pass, domain, r;

  # If init_connection is set, then setup the smb connection.
  if (!isnull(share))
  {
    login  = kb_smb_login();
    pass   = kb_smb_password();
    domain = kb_smb_domain();

    if ( hcf_init == 0 ) hotfix_check_fversion_init();
    r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if ( r != 1 ) return NULL;
  }

  if (isnull(max_recurse)) max_recurse = 1;
  # nb: limit how deep we'll recurse.
  if (level > max_recurse) return NULL;

  subdirs = NULL;
  if (isnull(dir_pat)) dir_pat = "";
ret = FindFirstFile(pattern:basedir + "\*" + dir_pat + "*");

  contents = make_list();
  while (!isnull(ret[1]))
  {
    if (file_pat && ereg(pattern:file_pat, string:ret[1], icase:TRUE))
      contents = make_list(contents, basedir+"\"+ret[1]);

    subsub = NULL;
    if ("." != ret[1] && ".." != ret[1] && level <= max_recurse)
      subsub  = list_dir(basedir:basedir+"\"+ret[1], level:level+1, file_pat:file_pat, max_recurse:max_recurse);
    if (!isnull(subsub))
    {
      if (isnull(subdirs)) subdirs = make_list(subsub);
      else subdirs = make_list(subdirs, subsub);
    }
    ret = FindNextFile(handle:ret);
  }

  # If we initiated a connection, now close it.
  if (!isnull(share)) NetUseDel(close:FALSE);

  if (isnull(subdirs)) return contents;
  else return make_list(contents, subdirs);
}

##
# Perform a version comparison for winsxs
#
# @param a version 1
# @param b version 2
#
# @return -1 if a < b
#          0 if a == b
#          1 if a > b
##
function _winsxs_version_cmp(a, b)
{
  local_var i;

  a = split(a, sep:'.', keep:FALSE);
  b = split(b, sep:'.', keep:FALSE);

  for (i=0; i < max_index(a); i++)
  {
    if (int(a[i]) < int(b[i]))
      return -1;
    else if (int(a[i]) > int(b[i]))
      return 1;
  }
  return 0;
}

##
# Returns the file version as a string, either from the KB or by
# calling GetFileVersion(). Assumes we're already connected to the
# correct share.
function _winsxs_get_file_version()
{
  local_var fh, file, ver, version;
  local_var pattern, matches, root;

  if (isnull(_FCT_ANON_ARGS[0])) return NULL;

  file = _FCT_ANON_ARGS[0];
  version = get_kb_item("SMB/FileVersions"+tolower(str_replace(string:file, find:"\", replace:"/")));
  if (isnull(version))
  {
    fh = CreateFile(
      file:file,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh))
    {
      ver = GetFileVersion(handle:fh);
      CloseFile(handle:fh);
      if (!isnull(ver))
      {
        version = ver[0] + "." + ver[1] + "." + ver[2] + "." + ver[3];
        set_kb_item(
          name:"SMB/FileVersions"+tolower(str_replace(string:file, find:"\", replace:"/")),
          value:version
        );
      }

      # At this point we know the file exists, we just don't have a version
      # We will have to attempt to get the version from the folder name
      if (isnull(version))
      {
        pattern = "_([0-9]+.[0-9]+.[0-9]+.[0-9]+)_";
        matches = eregmatch(pattern:pattern, string:file);
        if(!isnull(matches)) version = matches[1];
      }
    }
  }
  return version;
}

##
# Parses a properties file on Windows.
#
# @param path Path of file to parse.
# @param appname Application name for error messages if applicable.
# @remark Requires inclusion of misc_func.inc.
# @return array of key->value pairs if successful
#         NULL  otherwise
function smb_get_properties(path, appname)
{
  local_var contents;

  if (isnull(path) || (strlen(path) == 0))
  {
    err_print('smb_get_properties(): missing required arg "path"');
    return NULL;
  }

  if (isnull(appname))
  {
    err_print('smb_get_properties(): missing required arg "appname"');
    return NULL;
  }

  contents = hotfix_get_file_contents(path);

  hotfix_handle_error(error_code: contents['error'], appname:appname, file:path, exit_on_fail:TRUE);

  return parse_properties(contents['data']);
}

##
# Retrieves the list of all user directories and saves it in the KB
#
# @return List of user paths if successful
#         NULL otherwise
##
function hotfix_get_user_dirs()
{
  local_var appdir, dirpat, domain, hklm, iter, lcpaths, lcpath, login, pass;
  local_var path, paths, pdir, port, rc, root, share, user, ver;

  paths = get_kb_list("SMB/User Directory");
  if (!empty_or_null(paths))
  {
    paths = make_list(list_uniq(paths));
    return paths;
  }
  paths = make_list();

  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  pdir = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\ProfilesDirectory");
  if (pdir && stridx(tolower(pdir), "%systemdrive%") == 0)
  {
    root = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot");
    if (!isnull(root))
    {
      share = hotfix_path2share(path:root);
      pdir = share - '$' + ':' + substr(pdir, strlen("%systemdrive%"));
    }
  }
  RegCloseKey(handle:hklm);
  close_registry(close:FALSE);

  if (!pdir)
    return NULL;

  ver = get_kb_item_or_exit("SMB/WindowsVersion");

  share = hotfix_path2share(path:pdir);
  dirpat = ereg_replace(string:pdir, pattern:"^[A-Za-z]:(.*)", replace:"\1\*");

  port    =  kb_smb_transport();
  if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
  login   =  kb_smb_login();
  pass    =  kb_smb_password();
  domain  =  kb_smb_domain();

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel(close:FALSE);
    return NULL;
  }

  # 2000 / XP / 2003
  if (ver < 6)
    appdir += "\Local Settings\Application Data";
  # Vista / 7 / 2008
  else
    appdir += "\AppData\Local";

  lcpaths = make_array();
  paths = make_list();
  iter = FindFirstFile(pattern:dirpat);
  while (!isnull(iter[1]))
  {
    user = iter[1];
    iter = FindNextFile(handle:iter);

    if (user == "." || user == "..")
      continue;

    path = pdir + '\\' + user + appdir;

    lcpath = tolower(path);
    if (isnull(lcpaths[lcpath]))
    {
      lcpaths[lcpath] = path;
      paths = make_list(paths, path);
      set_kb_item(name:"SMB/User Directory", value:path);
    }
  }

  NetUseDel(close:FALSE);

  return paths;
}

##
# Searches uninstall key subkeys for installed product with display
# name matching a given pattern
#
# @param required pattern to match
#
# @return FALSE if displayname not found, subkey name if found
##
function hotfix_displayname_in_uninstall_key(pattern)
{
  local_var key, display_names;

  display_names =
    get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");

  if(isnull(display_names)) return FALSE;

  foreach key (keys(display_names))
    if (display_names[key] =~ pattern) return key;

  return FALSE;
}
