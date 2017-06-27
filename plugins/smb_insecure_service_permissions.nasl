#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65057);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/12 17:12:47 $");

  script_name(english:"Insecure Windows Service Permissions");
  script_summary(english:"Checks the file permissions of the service's binPath");

  script_set_attribute(attribute:"synopsis", value:
"At least one improperly configured Windows service may have a
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"At least one Windows service executable with insecure permissions was
detected on the remote host. Services configured to use an executable
with weak permissions are vulnerable to privilege escalation attacks.
An unprivileged user could modify or overwrite the executable with
arbitrary code, which would be executed the next time the service is
started. Depending on the user that the service runs as, this could
result in privilege escalation.

This plugin checks if any of the following groups have permissions to
modify executable files that are started by Windows services :

  - Everyone
    - Users
    - Domain Users
    - Authenticated Users");
  # http://travisaltman.com/windows-privilege-escalation-via-weak-service-permissions/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4e766b2");
  script_set_attribute(attribute:"solution", value:
"Ensure the groups listed above do not have permissions to modify or
write service executables. Additionally, ensure these groups do not
have Full Control permission to any directories that contain service
executables.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services_params.nasl", "smb_dom2sid.nasl");
  script_require_keys("SMB/svcs", "SMB/transport", "SMB/name", "SMB/login", "SMB/password");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");

global_var domain_users;

domain_sid = get_kb_item('SMB/domain_sid');
if (!isnull(domain_sid))
{
  domain_sid = hex2raw(s:domain_sid);
  domain_users = sid2string(sid:domain_sid) + '-513';
}

##
# Extracts the exe from a Windows service's configuration.
# Any quotes, arguments, or anything other than the path being
# executed gets removed
#
# e.g.
#   c:\windows\system32\svchost.exe -k netsvcs
# becomes
#   c:\windows\system32\svchost.exe
#
# @anonparam exe_setting the executable path setting of the service
# @return the path of the executable if it was obtained, or
#         NULL otherwise
##
function _get_service_exe()
{
  local_var exe_setting, exe, end_quote, match;
  exe_setting = _FCT_ANON_ARGS[0];

  if (isnull(exe_setting))
    return NULL;
  else
    exe_setting = strip(exe_setting);

  # if the setting has no spaces or quotes, the entire setting is the exe path
  if (exe_setting !~ '[" ]')
    return exe_setting;

  # if the setting starts with a quote, the exe path is in between the first and second quote
  if (exe_setting[0] == '"')
  {
    end_quote = stridx(exe_setting, '"', 1);
    if (end_quote == -1) return NULL;

    exe = substr(exe_setting, 1, end_quote - 1);
    if (strlen(exe) > 0)
      return exe;
    else
      return NULL;
  }

  # for all other cases, assume the end of the exe is marked by the first occurrence of anything that
  # looks like an extension (a dot plus three characters) followed by a space or the end of the string
  match = eregmatch(string:exe_setting, pattern:"^(.+\.\S{3})( |$)");
  if (isnull(match))
    return NULL;
  else
    return match[1];
}

##
# Gets the DACL of the given file
#
# @anonparam fh handle of the file to obtain the DACL for
#
# @return DACL associated with 'fh'
##
function _get_dacl()
{
  local_var fh, sd, dacl;
  fh = _FCT_ANON_ARGS[0];

  sd = GetSecurityInfo(handle:fh, level:DACL_SECURITY_INFORMATION);
  if (isnull(sd))
    return NULL;

  dacl = sd[3];
  if (isnull(dacl))
    return NULL;

  dacl = parse_pdacl(blob:dacl);
  if (isnull(dacl))
    return NULL;

  return dacl;
}

##
# For the given file, checks if the given permission is allowed for any of the following groups:
#
#   Everyone
#   Users
#   Domain Users
#   Authenticated Users
#
# It's possible other configurations may be vulnerable as well, but this should
# provide a good enough generic check
#
# @remark this function assumes the caller has already connected to the appropriate share
# @anonparam path path of the file to check. the drive should not be specified in the path
# @anonparam perm_to_check the file permission which (if granted) would be considered insecure. if this
#            is not specified, it defaults to FILE_WRITE_DATA
# @return a comma delimited string of groups that could exploit insecure permissions, or
#         NULL if none were found
##
function _insecure_file_perms()
{
  local_var path, perm_to_check, allowed, fh, dacl, ace, rights, type, sid, groups;
  path = _FCT_ANON_ARGS[0];
  perm_to_check = _FCT_ANON_ARGS[1];
  allowed = make_array();

  if (isnull(perm_to_check))
    perm_to_check = FILE_WRITE_DATA;

  if (isnull(path)) return NULL;

  fh = CreateFile(
    file:path,
    desired_access:STANDARD_RIGHTS_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh)) return NULL;

  dacl = _get_dacl(fh);
  CloseFile(handle:fh);
  if (isnull(dacl)) return NULL;

  foreach ace (dacl)
  {
    ace = parse_dacl(blob:ace);
    if (isnull(ace)) continue;

    rights = ace[0];
    type = ace[3];
    sid = sid2string(sid:ace[1]);
    if (isnull(sid)) continue;

    # ACES are stop on first match
    if (
      type == ACCESS_ALLOWED_ACE_TYPE && rights & perm_to_check == perm_to_check && isnull(allowed[sid]) &&
      (sid == '1-1-0' ||      # Everyone
       sid == '1-5-32-545' || # Users
       sid == '1-5-11' ||     # Authenticated Users
       (domain_users && sid == domain_users)) # Domain Users
    )
    {
      allowed[sid] = TRUE;
    }
    else if (
      type == ACCESS_DENIED_ACE_TYPE && rights & perm_to_check == perm_to_check && isnull(allowed[sid]) &&
      (sid == '1-1-0' ||      # Everyone
       sid == '1-5-32-545' || # Users
       sid == '1-5-11' ||     # Authenticated Users
       (domain_sid && sid == domain_sid + '-513')) # Domain Users
    )
    {
      allowed[sid] = FALSE;
    }
  }

  groups = make_list();

  foreach sid (keys(allowed))
  {
    if (allowed[sid])
    {
      if (sid == '1-1-0')
        groups = make_list(groups, 'Everyone');
      else if (sid == '1-5-32-545')
        groups = make_list(groups, 'Users');
      else if (sid == domain_users)
        groups = make_list(groups, 'Domain Users');
      else if (sid == '1-5-11')
        groups = make_list(groups, 'Authenticated Users');
    }
  }

  if (max_index(groups) == 0)
    return NULL;
  else
    return join(groups, sep:', ');
}

##
# For the given file, checks its directory to see if the Full Control permission is allowed
# for any of the following groups:
#
#  Everyone
#  Users
#  Domain Users
#  Authenticated Users
#
# It's possible other configurations may be vulnerable as well, but this should
# provide a good enough generic check
#
# @remark this function assumes the caller has already connected to the appropriate share
# @anonparam path path of the file whose dir should be checked. the drive should not be specified in the path
# @return a comma delimited string of groups that could exploit insecure permissions, or
#         NULL if none were found
##
function _insecure_dir_perms()
{
  local_var path, dir, parts, i;
  path = _FCT_ANON_ARGS[0];

  if (isnull(path)) return NULL;

  dir = '';
  parts = split(path, sep:"\", keep:TRUE);
  for (i = 0; i < max_index(parts) - 1; i++)
    dir += parts[i];

  # sanity check - this should never happen
  if (dir == '') return NULL;

  return _insecure_file_perms(dir, FILE_ALL_ACCESS);
}

# this gives a list of the entire command line used to start each service.
# this could include arguments, quotes, and other extras we're not interested in
exe_settings = get_kb_list_or_exit('SMB/svc/*/path');

# this extracts the exe from the configuration of each service, and keeps track of
# which service or services use the exe
exes = make_array(); # key = exe, value = list of services that use 'exe'
foreach key (keys(exe_settings))
{
  svc = key - 'SMB/svc/' - '/path';
  exe_setting = tolower(exe_settings[key]); # the same service might appear multiple times with different capitalization
  exe = _get_service_exe(exe_setting);
  if (isnull(exe)) continue; # error parsing the setting (e.g., unmatched quotes)

  if (isnull(exes[exe]))
    exes[exe] = make_list(svc);
  else
    exes[exe] = make_list(exes[exe], svc);
}

if (max_index(keys(exes)) == 0)
  exit(1, 'Unexpected error parsing exe paths.');

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();
port    =  kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

last_share = NULL;
report = NULL;

foreach exe (sort(keys(exes))) # sort the paths to minimize NetUseAdd() calls
{
  share = hotfix_path2share(path:exe);

  if (share != last_share)
  {
    if (!isnull(last_share))
      NetUseDel(close:FALSE);

    ret = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (ret != 1)
    {
      # TODO: it might be a better strategy to ignore any errors, and keep running
      # instead of existing prematurely
      NetUseDel();

      # report any results before bailing out
      if (!isnull(report))
      {
        if (report_verbosity > 0)
          security_hole(port:port, extra:report);
        else
          security_hole(port);

        exit(0);
      }
      else audit(AUDIT_SHARE_FAIL, share);
    }
    else last_share = share;
  }

  path = substr(exe, 2);
  details = NULL;

  if (groups = _insecure_file_perms(path))
    details += '\nFile write allowed for groups : ' + groups;
  if (groups = _insecure_dir_perms(path))
    details += '\nFull control of directory allowed for groups : ' + groups;

  if (isnull(details)) continue;

  report +=
    '\nPath : ' + exe +
    '\nUsed by services : ' + join(exes[exe], sep:', ') +
    details + '\n';
}

if (!isnull(last_share))
  NetUseDel();

if (isnull(report))
  audit(AUDIT_HOST_NOT, 'affected');

if (report_verbosity > 0)
  security_hole(port:port, extra:report);
else
  security_hole(port);
