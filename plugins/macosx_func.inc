#TRUSTED 312fb273355c66d56df015357d02c7739e9965c3a2806a165ef23de639e5a05fb2c7a22b7dfe7be8eac62d96b25369f301cf6637f70511885897f87428fd501a1c0a2a8efd5263282aac2da201cfd2b052b2f83d531a45356320975fbe5b7dc2724837dcc16e6f42407e68bda97b44e1cf8e8fb1a8dafdf9000b12bfa2644fb9b6a43b73b9872afe5efee04dd24fb0556c885fd87b6e53f4adce823d6fc2c3496df0d0234c959cdeb146a150080c28895d9f6052a59b6d88221f794be791b0ccf9a6d56660d2e91f20e645db6a7d4dc485b934baea7032d7521f521f9eb24a870848bea37fca6d47d81a435fd5341ddfc6354edc7f1b3d6f8a5b069a4e0b67dc5740908c2f370469e0661c357f3400890f284a541320f237612fa4efb6e789f362aecd22e2016678df1eedf3d6d25deb9da1cdf20ad4e51c718c3c67fc6916538b04fab9aa1682b14da7a90958d84328e93a2a675a18b0e33162ec90c38ded4879114b383d49293013af8d3c9033685b9b531a6539fcbdff40776f4f691f79567b0d1279ebf30784da1b56604ad963ef2c82cce4cef807e01d01a14243cc7b2c6a8ca40c0ea0fdbc6ce4d5540aacc0eaa1b72c7452a53105629985c9b4b0056ebd808be7ac91693243598e78661423ac47c6a1126baa7442cac9b6fabab17707ee11028e88f2d90810967121b86a67cdee4c18cc8e42421d0845bf00903c07fa
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# v1.7

##
# Generates OSX Bundle Version
#
# @param file filename of bundle
# @param path path to bundle
# @param label plist tag for the version info
# @param rsrc True for rsrc, otherwise false
#
# @category OSX
#
# @return Command to be used to get a bundle version
##
function _GetBundleVersionCmd(file, path, label, rsrc)
{
  local_var ret, suffix;
  local_var cmd;

  # This is only invoked by GetCarbonVersionCmd
  if ( rsrc )
  {
    suffix = "/rsrc";
    cmd = "perl -pe 's/[^ -~]/\\n/g'";
  }
  else
  {
    suffix = "/Contents/version.plist";
    cmd    = "cat";
 }

 file = str_replace(find:' ', replace:'\\ ', string:file);

 if ( !isnull(path) )
   {
   path = str_replace(find:' ', replace:'\\ ', string:path);
   ret = "cd " + path + " 2>/dev/null && ";
   }
 else
   ret = "";


 ret += cmd + " " + file + suffix + "|grep -A 1 " + label + " " + '| tail -n 1 | sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
 return ret;
}

##
# Generates OSX Bundle Version
#
# @param file filename of bundle
# @param path path to bundle
# @param long If true uses CFBundleVersion otherwise CFBundleShortVersion
#
# @category OSX
#
# @return Command to be used to get a bundle version
##
function GetBundleVersionCmd(file, path, long)
{
 if ( long )
  return _GetBundleVersionCmd(file:file, path:path,label:"CFBundleVersion", rsrc:FALSE);
 else
  return _GetBundleVersionCmd(file:file, path:path,label:"CFBundleShortVersion", rsrc:FALSE);
}

##
# Generates OSX Bundle Version
#
# @param file
# @param path
#
# @category OSX
#
# @return Command to be used to get a bundle version
##
function GetCarbonVersionCmd(file, path)
{
 return _GetBundleVersionCmd(file:file, path:path,label:"CFBundleVersion", rsrc:TRUE);
}

##
# Executes a command on localhost or via ssh.
#
# @param cmd Command to be executed on the target host.
# @param exit_on_fail True/False if the script should exit on fail, returns NULL if False and fails.
#
# @category OSX
#
# @return The result of the executed command or NULL on failure.
##
function exec_cmd(cmd, exit_on_fail)
{
  local_var ret, buf;

  if (isnull(exit_on_fail))
    exit_on_fail = FALSE;

  if (islocalhost())
    buf = pread(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = ssh_open_connection();

    if (!ret)
    {
      if (exit_on_fail) exit(1, "ssh_open_connection() failed.");
      else return NULL;
    }

    buf = ssh_cmd(cmd:cmd);
    ssh_close_connection();
  }

  if (buf) buf = chomp(buf);
  return buf;
}

##
# Executes a array of unique commands on localhost or via ssh.
#
# @param cmds Array of unique commands to be executed on the target host.
# @param exit_on_fail True/False if the script should exit on fail, returns NULL if False and fails.
#
# @category OSX
#
# @return An hash of the results of the executed commands or NULL on failure.
##
function exec_cmds(cmds, exit_on_fail)
{
  local_var command, ret, buf, results;

  if (typeof(cmds) != 'array')
    exit(1, "Invalid type for the 'cmds' argument.");

  if (isnull(exit_on_fail))
    exit_on_fail = FALSE;

  results = make_array();
  cmds = list_uniq(cmds);

  if (!islocalhost())
  {
    ret = ssh_open_connection();

    if (!ret)
    {
      if (exit_on_fail)
        exit(1, "ssh_open_connection() failed.");
      else
        return NULL;
    }
  }

  foreach command (cmds)
  {
    buf = "";

    if (islocalhost())
      buf = pread(cmd:"/bin/bash", argv:make_list("bash", "-c", command));
    else
    {
      buf = ssh_cmd(cmd:command);

      if(isnull(buf))
      {
        if(exit_on_fail == TRUE)
          exit(1, "ssh_cmd() failed.");
      }
    }

    if (buf)
      buf = chomp(buf);

    results[command] = buf;
  }

  if (!islocalhost()) ssh_close_connection();

  return results;
}


##
# Gets the list of user directories
#
# @param all True/False if the script should extract all user directories or just those of regular users (ie, with an id > 499)
#
# @category OSX
#
# @return An array in which the keys are the usernames and the values are the home directories.
##
function get_users_homes(all)
{
  local_var cmd, data, home, homes, id, key, line, match, res, val;

  cmd = 'echo ; /usr/bin/dscl  . -readall /Users NFSHomeDirectory UniqueID';
  res = exec_cmd(cmd:cmd);
  if (!strlen(res)) return NULL;

  homes = make_array();
  foreach line (split(res, keep:FALSE))
  {
    match = eregmatch(pattern:"^([^: ]+): +(.+)$", string:line);
    if (match)
    {
      key = match[1];
      val = match[2];
      data[tolower(key)] = val;
    }

    if (!isnull(data['uniqueid']) && !isnull(data['recordname']) && !isnull(data['nfshomedirectory']))
    {
      id = data['uniqueid'];
      if (all || id > 499)
      {
        key = data['recordname'];
        val = data['nfshomedirectory'];
        homes[key] = val;
      }

      data = make_array();
    }
  }
  return homes;
}
