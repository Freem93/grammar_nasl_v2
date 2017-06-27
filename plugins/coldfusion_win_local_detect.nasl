#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55514);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/06/13 20:14:28 $");

  script_name(english:"ColdFusion Installed on Microsoft Windows (credentialed check)");
  script_summary(english:"Checks to see if ColdFusion is installed");

  script_set_attribute(attribute:"synopsis", value:"A web application platform is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"Adobe ColdFusion (formerly Macromedia ColdFusion), a rapid application
development platform, is installed on the remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"https://www.adobe.com/products/coldfusion-family.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:macromedia:coldfusion");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("smb_func.inc");
include("byte_func.inc");

global_var instances, name, port, login, pass, domain, files_to_find;
instances = make_array();
name   = kb_smb_name();
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

# files that we're interested in extracting from cfusion.jar,
# which gives us version and build information
files_to_find = make_array(
  'META-INF/MANIFEST.MF', TRUE,
  'coldfusion/Version.class', TRUE
);

##
# attempts to extract all 'files_to_find' from the given jar
#
# for more on the file format refer to http://www.pkware.com/documents/casestudies/APPNOTE.TXT
#
# @anonparam fh file handle of jar to search through
# @return a hash where the key is the filename, and value is the file contents iff all 'files_to_find' were discovered,
#         NULL otherwise
##
function find_files_in_jar()
{
  local_var fh, jar_len, field, i, magic, version, bitflag, compression, mtime, mdate, crc, compressed_len, uncompressed_len;
  local_var filename_len, extra_field_len, filename, compressed_data, uncompressed_data, file_data, files, files_found;
  fh = _FCT_ANON_ARGS[0];

  set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);
  jar_len = GetFileSize(handle:fh);
  i = 0;
  files_found = 0;
  files = NULL;  # key = filename, value = data

  while (i < jar_len)
  {
    field = ReadFile(handle:fh, offset:i, length:4); i += 4;
    magic = getdword(blob:field, pos:0);
    if (magic != 0x04034b50)
    {
      debug_print("Bad magic: " + hexstr(magic));
      return NULL;
    }

    field = ReadFile(handle:fh, offset:i, length:2); i += 2;
    version = getword(blob:field, pos:0);

    field = ReadFile(handle:fh, offset:i, length:2); i += 2;
    bitflag = getword(blob:field, pos:0);

    field = ReadFile(handle:fh, offset:i, length:2); i += 2;
    compression = getword(blob:field, pos:0);

    field = ReadFile(handle:fh, offset:i, length:2); i += 2;
    mtime = getword(blob:field, pos:0);

    field = ReadFile(handle:fh, offset:i, length:2); i += 2;
    mdate = getword(blob:field, pos:0);

    field = ReadFile(handle:fh, offset:i, length:4); i += 4;
    crc = getdword(blob:field, pos:0);

    field = ReadFile(handle:fh, offset:i, length:4); i += 4;
    compressed_len = getdword(blob:field, pos:0);

    field = ReadFile(handle:fh, offset:i, length:4); i += 4;
    uncompressed_len = getdword(blob:field, pos:0);

    field = ReadFile(handle:fh, offset:i, length:2); i += 2;
    filename_len = getword(blob:field, pos:0);

    field = ReadFile(handle:fh, offset:i, length:2); i += 2;
    extra_field_len = getword(blob:field, pos:0);

    filename = ReadFile(handle:fh, offset:i, length:filename_len); i += filename_len;

    i += extra_field_len;

    file_data = ReadFile(handle:fh, offset:i, length:compressed_len); i += compressed_len;

    # the manifest gives us the build number, the class file gives us the version (x,y,z)
    if (files_to_find[filename])
    {
      if (compression == 0)  # no compression
      {
        files[filename] = file_data;
        if (++files_found == 2) break;
      }
      else if (compression == 8)  # deflate
      {
        uncompressed_data = zlib_decompress(data:file_data, length:uncompressed_len);
        files[filename] = uncompressed_data;
        if (++files_found == 2) break;
      }
      else
      {
        # research indicates the files we're interested in are always compressed using deflate
        # for now we'll ignore anything else
        debug_print("Unknown compression method: " + compression);
        break;
      }
    }

    # skip over the data descriptor block if it's present
    if (bitflag & 0x4)
    {
      field = ReadFile(handle:fh, offset:i, length:12);
      i += 12;
    }
  }

  if (files_found < 2)
  {
    if (files_found == 0)
      debug_print("The desired files weren't found in the jar file.");
    else
      debug_print("Only " + join(files, sep:'') + " was found in the jar file.");

    return NULL;
  }

  return files;
}

##
# Checks to see if the given ColdFusion instance is valid by trying to get
# its version number, build number, and any hotfixes it may have.  If this
# information is obtained, it's stored in the global hash 'instances'
#
# @anonparam name instance name to check
##
function check_instance()
{
  local_var name, cfroot, share, rc, ver;
  name = _FCT_ANON_ARGS[0];
  cfroot = instances[name]['cfroot'];

  share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:cfroot);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
    debug_print('get_instances: Can\'t connect to '+share+' share.');
  else
  {
    get_version(name);
    ver = instances[name]['version'];
    if (!isnull(ver)) get_hotfixes(name, ver);
  }
  NetUseDel(close:FALSE);
}

##
# Tries to get the version number (x.y.z) and build number of the given ColdFusion instance.
# if this function succeeds, the information is stored in the 'instances' global variable
#
# This function assumes the plugin has already been connected to the share
# where the instance is located
#
# @anonparam name name of the instance to get the version for
##
function get_version()
{
  local_var name, path, jar, fh, files, match, build, version, file_data;
  name = _FCT_ANON_ARGS[0];

  if (instances[name]['type'] == 'Server')
    path = instances[name]['cfroot'] + "\lib\cfusion.jar";
  else if (instances[name]['type'] == 'Multiserver')
    path = instances[name]['cfroot'] + "\WEB-INF\cfusion\lib\cfusion.jar";

  jar = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1', string:path);

  fh = CreateFile(
    file:jar,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (fh)
  {
    # tries to extract the files containing the version & build from the jar
    files = find_files_in_jar(fh);
    CloseFile(handle:fh);

    if (!isnull(files))
    {
      match = eregmatch(string:files['META-INF/MANIFEST.MF'], pattern:'Implementation-Version: ([0-9]+)');
      if (!isnull(match))
      {
        build = match[1];
        instances[name]['build'] = match[1];
      }

      # need to get rid of the nulls in order for the regex function to work
      file_data = str_replace(string:files['coldfusion/Version.class'], find:'\x00', replace:'');
      match = eregmatch(string:file_data, pattern:'([0-9]+,[0-9]+,[0-9]+),');
      if (!isnull(match))
      {
         version = str_replace(string:match[1], find:',', replace:'.');
         instances[name]['version'] = version;
      }
    }
  }
  else debug_print('Unable to open: ' + path);
}

##
# gets a list of hotfixes for the given instance. if this function succeeds, the results
# are put in the 'instances' global variable
#
# @anonparam name name of the instance to get hotfixes for
# @anonparam ver  version of the 'name' instance
##
function get_hotfixes()
{
  local_var name, ver, update_path, dir, pattern, fh, match, type, id;
  name = _FCT_ANON_ARGS[0];
  ver = str_replace(string:_FCT_ANON_ARGS[1], find:'.', replace:'');

  if (instances[name]['type'] == 'Server')
    update_path = instances[name]['cfroot'] + "\lib\updates";
  else if (instances[name]['type'] == 'Multiserver')
    update_path = instances[name]['cfroot'] + "\WEB-INF\cfusion\lib\updates";

  dir = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1', string:update_path);
  pattern = strcat(dir, "\*hf", ver, "*.jar");

  fh = FindFirstFile(pattern:pattern);
  while (!isnull(fh[1]))
  {
    # Skip directories.
    if (fh[2] & FILE_ATTRIBUTE_DIRECTORY == 0)
    {
      # Hotfix jars are in the format:
      # hfxyz-nnnn.jar  xyz = CF version, nnnn hotfix number
      # e.g.
      # hf800-1875.jar    hf = regular hotfix, 800 = CF 8.0.0, 1875 = seemingly random number
      # hf800-00001.jar   hf = regular hotfix, 800 = CF 8.0.0, 00001 = zero padded numbers can supersede the random number hotfixes
      # chf800-0001.jar   chf = cumulative hotfix, 800 = CF 8.0.0, 00001 = CHF number. these can supersede the previous two types
      #
      # this is all undocumented and, at best, an educated guess
      match = eregmatch(string:fh[1], pattern:"^(c?hf)" + ver + "-?([0-9]+).jar$");
      if (!isnull(match))
      {
        type = match[1];
        id = match[2];

        if (isnull(instances[name][type]))
          instances[name][type] = make_list();

        instances[name][type] = make_list(instances[name][type], id);
      }
    }

    fh = FindNextFile(handle:fh);
  }
}

##
# gets a list of instances in the given multiserver environment
#
# @anonparam path root path of the multiserver environment to get instances for
# @return a list of instances if any were discovered,
#         an empty list otherwise
##
function get_instances()
{
  local_var path, share, dir, rc, fh, length, blob, name, instance_dir, line, match, connector_path;
  path = _FCT_ANON_ARGS[0];

  share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:path);
  dir = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1', string:path);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel(close:FALSE);
    debug_print('get_instances: Can\'t connect to '+share+' share.');
    return;
  }

  fh = CreateFile(
    file:dir + '\\lib\\servers.xml',
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    length = GetFileSize(handle:fh);
    if (length > 32678) length = 32678;
    blob = ReadFile(handle:fh, offset:0, length:length);
    CloseFile(handle:fh);

    # poor man's xml parser, which should work fine since
    # this file isn't supposed to be edited manually
    foreach line (split(blob, sep:'\n', keep:FALSE))
    {
      if ('<server>' >< line)
      {
        name = NULL;
        instance_dir = NULL;
        continue;
      }

      match = eregmatch(string:line, pattern:'<name>([^<]+)</name>');
      if (!isnull(match))
      {
        name = match[1];
        continue;
      }

      match = eregmatch(string:line, pattern:'<directory>([^<]+)</directory>');
      if (!isnull(match))
      {
        instance_dir = str_replace(string:match[1], find:'{jrun.home}', replace:path);
        instance_dir = str_replace(string:instance_dir, find:'/', replace:'\\');

        if (instance_dir !~ '\\\\cfusion$')
          instance_dir += '\\cfusion.ear\\cfusion.war';
        else
          instance_dir += '\\cfusion-ear\\cfusion-war';
      }

      if ('</server>' >< line && !isnull(name) && !isnull(instance_dir))
      {
        instances[name]['webroot'] = instance_dir;
        instances[name]['cfroot'] = instance_dir;
        instances[name]['jrun_home'] = path;
        instances[name]['type'] = 'Multiserver';

        # it appears the optional 3rd party connector can only be used with the 'default' instance
        if (instance_dir =~ '\\\\cfusion-war')
        {
          connector_path = get_connector_path(dir);
          if (!isnull(connector_path))
            instances[name]['webroot'] = connector_path;
        }
      }
    }
  }
  else debug_print('Unable to open ' + dir + '\\lib\\servers.xml');

  NetUseDel(close:FALSE);
}

##
# gets the webroot of a multiserver instance when it's hosted by a 'connector',
# i.e. a 3rd party web server like IIS, Apache, Sun ONE
#
# this function assumes it's already connected to the relevant
# share, and 'path' is relative to that share
#
# @anonparam path root path of the multiserver environment
# @return path to the webroot if it was found,
#         NULL otherwise
##
function get_connector_path()
{
  local_var path, instance, bat, fh, length, blob, match, webroot;
  path = _FCT_ANON_ARGS[0];
  webroot = NULL;

  bat = FindFirstFile(pattern:path + "\ConnectorInstall*.bat");
  while (!isnull(bat[1]))
  {
    fh = CreateFile(
      file:path + '\\' + bat[1],
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh))
    {
      length = GetFileSize(handle:fh);
      if (length > 1024) length = 1024;  # this is going to be 2 lines of text, was less than 1k
      blob = ReadFile(handle:fh, offset:0, length:length);
      CloseFile(handle:fh);

      match = eregmatch(string:blob, pattern:'-cfwebroot *"([^"]+)"');
      if (!isnull(match))
      {
        webroot = match[1];
        break;
      }
    }
    bat = FindNextFile(handle:bat);
  }

  return webroot;
}


#
# plugin starts here
#

get_kb_item_or_exit('SMB/Registry/Enumerated');

list = get_kb_list('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
if (isnull(list)) audit(AUDIT_KB_MISSING, "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");

multiserver = make_list();

# enumerate possible multiserver installs
foreach key (keys(list))
{
  prod = list[key];
  if (isnull(prod)) continue;

  # < 8 does not have this key it seems
  if (prod =~ 'Adobe ColdFusion [89] with JRun 4')
  {
    key -= 'SMB/Registry/HKLM/';
    key -= '/DisplayName';
    key = str_replace(string:key, find:'/', replace:'\\');

    multiserver = make_list(multiserver, key);
  }
}

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:'IPC$');
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

# Connect to remote registry
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

# get Multiserver install path(s)
multiserver_paths = make_list();
foreach key (multiserver)
{
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:'InstallLocation');

    if(isnull(item))
    {
      item = RegQueryValue(handle:key_h, item:'DisplayIcon');
      if(!isnull(item))
      {
        tmp = str_replace(find:'"', replace:"", string:item[1]);
        tmp = str_replace(find:"'", replace:"", string:tmp);

        match = eregmatch(pattern:"^(.+)\\[^\\]*$", string:tmp);
        if(!isnull(match) && !isnull(match[1]))
          item[1] = match[1];
        else item = NULL;
      }
    }

    if(!isnull(item))
      multiserver_paths = make_list(multiserver_paths, item[1]);

    RegCloseKey(handle:key_h);

  }
}

# get (single) Server install path(s)
keys = make_list('SOFTWARE\\Adobe\\Install Data', 'SOFTWARE\\Macromedia\\Install Data');

foreach key (keys)
{
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    info = RegQueryInfoKey(handle:key_h);
    for (i=0; i<info[1]; ++i)
    {
      subkey = RegEnumKey(handle:key_h, index:i);
      match = eregmatch(string:subkey, pattern:"^(Adobe ColdFusion|ColdFusion MX) (\d+)$");
      if (isnull(match)) major = NULL;
      else major = match[1];

      if (!isnull(major))
      {
        key2 = key + "\" + subkey;
        key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
        if (!isnull(key2_h))
        {
          cfroot = RegQueryValue(handle:key2_h, item:"CFMXRoot");
          webroot = RegQueryValue(handle:key2_h, item:"WebRoot");

          if (!isnull(cfroot) && !isnull(webroot))
          {
            # we'll generate a bogus instance name just to have a unique key.
            name = strcat('Server-', major, '-', rand());
            instances[name]['cfroot'] = cfroot[1];
            instances[name]['type'] = 'Server';

            if (isnull(webroot[1]))
              instances[name]['webroot'] = cfroot[1] + "\wwwroot";
            else
              instances[name]['webroot'] = webroot[1];
          }
          RegCloseKey(handle:key2_h);
        }
      }
    }
    RegCloseKey(handle:key_h);
  }
}

RegCloseKey(handle:hklm);

# check if any potential multiserver or single server installs were detected in the registry
if (max_index(multiserver_paths) == 0 && max_index(keys(instances)) == 0)
{
  NetUseDel();
  audit(AUDIT_NOT_INST, "ColdFusion");
}
else NetUseDel(close:FALSE);

# gets the path of each instance used in a multiserver install. this info is
# stored in the global variable 'instances'
foreach path (multiserver_paths)
  get_instances(path);

# Checks if each instance is valid, and if so, collects version, build, and hotfix info
foreach name (keys(instances))
  check_instance(name);

NetUseDel();

info = NULL;

# Checks if any of the instances are valid, and starts building plugin output
foreach name (keys(instances))
{
  # we'll determine whether or not an instance is valid based on whether
  # we were able to determine its version number
  ver = instances[name]['version'];
  if (isnull(ver)) continue;

  # some instance names are artificially created by this plugin just to provide
  # a way to uniquely identify instances. they should only be used as a way of
  # getting instances from the KB, and should not be used in reports
  set_kb_item(name:'SMB/coldfusion/instance', value:name);
  set_kb_item(name:'SMB/coldfusion/' + name + '/version', value:ver);
  if (instances[name]['build'])
  {
    build = instances[name]['build'];
    set_kb_item(name:'SMB/coldfusion/' + name + '/build', value:build);
  }
  if (instances[name]['type'])
  {
    type = instances[name]['type'];
    set_kb_item(name:'SMB/coldfusion/' + name + '/type', value:type);
  }
  if (instances[name]['cfroot'])
  {
    cfroot = instances[name]['cfroot'];
    set_kb_item(name:'SMB/coldfusion/' + name + '/cfroot', value:cfroot);
  }
  if (instances[name]['webroot'])
  {
    webroot = instances[name]['webroot'];
    set_kb_item(name:'SMB/coldfusion/' + name + '/webroot', value:webroot);
  }
  if (instances[name]['jrun_home'])
  {
    jrun_home = instances[name]['jrun_home'];
    set_kb_item(name:'SMB/coldfusion/' + name + '/jrun_home', value:jrun_home);
  }

  info +=
    '\n    ColdFusion root : ' + cfroot +
    '\n    Web root        : ' + webroot +
    '\n    Version         : ' + ver;

  if (!isnull(build)) info += '.' + build;

  info += '\n    Instance type   : ' + type;

  foreach hf (instances[name]['hf'])
    set_kb_item(name:'SMB/coldfusion/' + name + '/hf', value:hf);

  foreach chf (instances[name]['chf'])
    set_kb_item(name:'SMB/coldfusion/' + name + '/chf', value:chf);

  if (max_index(instances[name]['hf']) > 0)
    info += '\n    Hotfixes : ' + join(instances[name]['hf'], sep:', ');
  if (max_index(instances[name]['chf']) > 0)
    info += '\n    Cumulative Hotfixes : ' + join(instances[name]['chf'], sep:', ');

  info += '\n';
}

if (isnull(info))
  exit(0, 'No valid ColdFusion instances were detected.');

if (report_verbosity > 0)
{
  report = '\nNessus detected the following ColdFusion instances :\n' + info;
  security_note(port:port, extra:report);
}
else security_note(port);
