#TRUSTED 81e35056a900f2ea5181556eb3e966a732118aa2c34640068f55da2ea69c1d4f2ae26ee32dcde9d4c901a34860dba4dd0625a03b70fcc4784e2e9a0027d5ee407acdd792502340567df5d2e6d0f3b841fc4553926b4bf15ff8b4d6045bfbf78102cc01e294cf5ca9da6e7c5102879de082d97c8e9ce9f6cd118eff5b77d5ccfae8d0094bac8c8754fd9493424fc8365169ea48d278d97754a03d4d491f4df41de4b38f587bf3fc896d917010ed4e1c7a37baf84c4543a62b0684e3179b1f76d409d68edcbeed7a2f3fef8171eff85f4d162c22ad92a0d3a7d0a40ba4191f5a4141d81c3f3100023eff10e64d4954bbb1257d3b53c0ce71be62a5c9b10a16eee6d5fc4782471418e5f4328d608c4e2111c96746c8607e788b4ed75cf214793e781492e8c082d2257c3d1540b12976b2be6c8443cbf1ba237256d22e1f51d3819adfe2f609f28b80bdc94fea7d9f42c91fd5ba7858e84602431f87bb936eefac4b9f3a5b326f6662441dffeacc5cd49cff74f77ef92213bfadbd61a55f7d7185b5bf4cf264dc8f1917ecefb5f891de60a2512870f3550eb9e6414c6fa5023ac606d7b76067d053e30444c1b79ff6781b633e312f8d5750d2160f2588e87cf7574fe13a82dbb191adc1c8d748f6449378b66a3f9deece5ae8d75aa5f087bc057296ce0f393ee66662ad0f5b76370f28ed4ee0a3006192e27c32818f38610b83ded5
#------------------------------------------------------------------------------
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# find_cmd.inc
#
# Revision: 1.4
#
# @include hostlevel_func.inc
# @include ssh_func.inc
# @include telnet_func.inc

global_var timeout_exists, xautofs_option_exists, automount_running, timedout,
           FIND_OK, FIND_FAIL;

FIND_OK = 1;
FIND_FAIL = 2;

timeout_exists = NULL;
xautofs_option_exists = NULL;
path_option_exists = NULL;

automount_running = NULL;
timedout = FALSE;

# only allow whitelisted characters to prevent command injection
# strings starting with '-' aren't allowed unless surrounded by quotes
find_check_pat = '^(( *[*A-Za-z0-9_./\\[\\]][*A-Za-z0-9_.\\-/\\[\\]]*)*|'+
                 '(\'[*A-Za-z0-9_.\\-/\\[\\] ]*\')|'+
                 '("[*A-Za-z0-9_.\\-/\\[\\] ]*"))$';
##
# Runs find cmd on *nix systems
#
# @param  path_patterns  List of path / filename pattern(s) we are looking for
# @param  start  Path to start searching from 
# @param  maxdepth  Max depth to traverse when searching (optional)
# @param  timeout  Timeout parameter for command (defaults to 240 seconds)
#
# @return list list[0] is return status, list[1] is error message
#              or result of command
##

function find_cmd(path_patterns, start, maxdepth, timeout, exit_on_fail)
{
  local_var cmd, buf, startpath, excludefs, array, filter, err, xautofs, 
            find_cmd_str, i, egrep_str, path_opt, path, md_param;

  if(isnull(exit_on_fail)) exit_on_fail = FALSE;

  if(isnull(path_patterns))
  {
    err = "Missing path_patterns argument.";
    if(exit_on_fail) exit(0, err);
    return make_list(FIND_FAIL, err);
  }

  if(isnull(start))
  {
    err = "Missing start argument.";
    if(exit_on_fail) exit(0, err);
    return make_list(FIND_FAIL, err);
  }

  init_find_cmd();

  # prevent potential command injection
  for (i=0; i<max_index(path_patterns); i++)
  {
    path = path_patterns[i];
    if(path !~ find_check_pat)
    {
      err = "Supplied path string contains disallowed characters.";
      if(exit_on_fail) exit(0, err);
      return make_list(FIND_FAIL, err);
   }
   
   # prepare path for egrep
   if(!path_option_exists)
   {
     path = str_replace(find:"\", replace:"\\", string:path);
     path = str_replace(find:".", replace:"\.", string:path);
     path = str_replace(find:"[", replace:"\[", string:path);
     path = str_replace(find:"*", replace:".*", string:path);
     path = '^' + path;

     path_patterns[i] = path;
   }
  }

  if(start !~ find_check_pat)
  {
    err = "Supplied start string contains disallowed characters.";
    if(exit_on_fail) exit(0, err);
    return make_list(FIND_FAIL, err);
  }

  timedout = FALSE;

  if(isnull(timeout)) timeout = 240;

  # we don't want to run the find command on systems running autofs unless the
  # find command allows us to ignore traversing those shares  
  if(!xautofs_option_exists && automount_running && !thorough_tests)
  {
    err = "The remote filesystem cannot be searched due to autofs. Enable thorough test to override.";
    if(exit_on_fail) exit(0, err);
    return make_list(FIND_FAIL, err);
  }

  filter = "";

  # setup the find command
  startpath = "/";
  excludefs = " -fstype nfs -prune -o -fstype cifs -prune -o -fstype smbfs " +
              "-prune -o -fstype afs -prune -o -fstype sysfs -prune -o " +
              "-fstype proc -prune";

  xautofs = '';
  if(xautofs_option_exists) xautofs = " -xautofs";

  md_param = '';
  if(!isnull(maxdepth) && maxdepth =~ "^[0-9]+$")
     md_param = " -maxdepth " + maxdepth + " ";

    # see if we were given a different start location than '/'
  if (!isnull(start)) startpath = start;

  path_opt = '';
  if(path_option_exists)
    path_opt = '-a \\( -path \'' + join(path_patterns, sep:'\' -o -path \'') + '\' \\)'; 
  
  egrep_str = '';
  if(!path_option_exists)
    egrep_str = " | egrep '" + join(path_patterns, sep:'|') + "'";   

  find_cmd_str = 'find ' + startpath + ' ' + md_param + xautofs +
                 ' -follow \\( -not \\( ' +
                 excludefs + ' \\) ' + path_opt + ' \\) 2>/dev/null' + egrep_str;
  
  if (timeout_exists)
  {
    # timeout command exists so use it
    cmd = 'timeout -s9 ' + timeout + 's ' + find_cmd_str + '; echo $?';
  }
  else
  {
    cmd = find_cmd_str + ' & NFP=$! ; sw(){ to="' +
          timeout +
          '" ; (( i = to )) ; while (( i > 0 )) ; do kill -0 $NFP || exit 0 ;' +
          ' sleep 1 ; (( i -= 1 )) ; done ; kill $NFP ; echo "TERMINATED" ;' +
          ' } ; sw "$to" 2>/dev/null';
  }
  buf = run_cmd_template(template:cmd);
  # Determine if the command timed out 
  if (buf['data'])
  {
    array = split(chomp(buf['data']));

    if (timeout_exists)
    {
      # Return Code is 137 if timed out 
      if (array[max_index(array)-1] == "137")
        timedout = TRUE;
    }
    else
    {
      if (array[max_index(array)-1] == "TERMINATED")
        timedout = TRUE;
    }
    # Delete garbage from timeout check
    if(timedout)
      array[max_index(array)-1] = '';
    # Reconstruct buf
    buf = join(array, sep:'');
  }
  # In some systems where the timeout command does not exists
  # the command sends nothing in return. In that case set buf to empty
  else
    buf = '';

  return make_list(FIND_OK, buf);
}

##
# Initialize find command
##
function init_find_cmd()
{
  if(isnull(timeout_exists)) _does_timeout_exist();
  if(isnull(xautofs_option_exists)) _is_xautofs_option();
  if(isnull(path_option_exists)) _is_path_option();
  if(isnull(automount_running)) _is_automount_running();
}

##
# Check if xautofs option for find is available
##
function _is_xautofs_option()
{
  local_var buf;
 
  xautofs_option_exists = get_kb_item("Host/find_cmd_options/xautofs");
  if(!isnull(xautofs_option_exists)) return;

  xautofs_option_exists = FALSE;

  buf = info_send_cmd(cmd:"find " + rand_str(length:20) + " -xautofs 2>&1");

  if('No such file or directory' >< buf &&
     'bad option' >!< buf && 'unknown predicate' >!< buf &&
     'illegal option' >!< buf)
    xautofs_option_exists = TRUE;
  
  # cache finding
  replace_kb_item(name:"Host/find_cmd_options/xautofs", value:xautofs_option_exists);
}

##
# Check if path option for find is available
##
function _is_path_option()
{
  local_var buf;

  path_option_exists = get_kb_item("Host/find_cmd_options/path");
  if(!isnull(path_option_exists)) return; 

  path_option_exists = TRUE;

  buf = info_send_cmd(cmd:"find " + rand_str(length:20) + " -path");
  buf = tolower(buf);

  if('bad option' >< buf || 'unknown predicate' >< buf ||
     'illegal option' >< buf)
    path_option_exists = FALSE;

  # path_option_exists = FALSE;
  # cache finding
  replace_kb_item(name:"Host/find_cmd_options/path", value:path_option_exists);
}

##
# Check if automount process is running
##
function _is_automount_running()
{
  local_var buf;

  automount_running = get_kb_item("Host/find_cmd_options/automount_running");
  if(!isnull(automount_running)) return;

  automount_running = FALSE;

  buf = info_send_cmd(cmd:'ps -aef');
  if (buf && 'automount' >< buf)
    automount_running = TRUE;
  
  # cache finding
  replace_kb_item(name:"Host/find_cmd_options/automount_running", value:automount_running);
}

##
# Check if timeout command exists
##
function _does_timeout_exist()
{
  local_var buf;

  timeout_exists = get_kb_item("Host/find_cmd_options/timeout_exists");
  if(!isnull(timeout_exists)) return;

  timeout_exists = FALSE;

  buf = info_send_cmd(cmd: 'type timeout 2>/dev/null');
  if (buf && 'not found' >!< buf)
    timeout_exists = TRUE;
  
  replace_kb_item(name:"Host/find_cmd_options/timeout_exists", value:timeout_exists);
}
