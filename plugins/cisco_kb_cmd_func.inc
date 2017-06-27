#TRUSTED 1d707e09e294a3caba450c34887da42693878b056dd663bb1066420a74d6db471ee4fba4a97f244c7bbeeb422c1fdfc5ef6c63110d78ba5d268ec80b0ae9bc0e847215338a43c1e21e37434660cacf8a3c53dad2b1d35647c8512191b9fbe833004c5e4287197073ed7ffeea3922a224730f6a58bfc2dca58658a1683abac2a5bbca135f435bcd39599d09928d08b685feb8e9cce7375d1d7204cbac5f7d372025fc14196d0922b77fd9b5e22beadd9d1dd53315fe7cc469507ebdbb44a54bb6b7d5ffd4e1c75a29f82c5dbb5be0da06d617eb284af05defea8243ea65501ac8da7fe9b2e541038b52465f1ae0aa737172d724acbd135acd7d02bf466248159095c9b86f7096f93cdc514066c27b3307980bb0657acaf15327cd5f00d023f799c3dc30bd23760ec67aa9d8acf5dfbbe00711203cdb749b638613834df906cb92b4799cfa128f32b2680f22166e6a45d41ee6dcd989679caf5d55c9ad82e36a17f8bf907e81cd9544a66c95890e1a58a0037213f14bbfcd6f7134f2a88162b9985b97e05d5f12ee76c1425789b65f83c3bd7e95cbfe049c275dd5f0d5e8c8550560db92ef3a2445dceaca36a636ea4f0e442fec6167cc7b3d6d042bfe40734da704e8823d6b4f6cada33f8171c4b77ea253cca98ee31f27b3ef586dd9fff6b5c93690306dd8de049050a3306bfa4860140bb8b5fb9d49ccfc537c76509984ec3e
#
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision: 1.9
###

include("ssh_func.inc");
include("hostlevel_funcs.inc");

##
# Attempt to determine if the enable password is required
#
# @return 1 is yes, 0 if no
##
function cisco_needs_enable()
{
  local_var buf, prompt;

  buf = _FCT_ANON_ARGS[0];

  # if local checks are not enabled, then there is no need for enable
  if (!get_kb_item("Host/local_checks_enabled")) return 0;

  # if buf is empty/blank then assume enable is NOT needed
  if (!buf) return 0;

  # check for various error messages used to identify when level 15
  # privs are needed
  # 
  # error message for IOS XR
  if ("% This command is not authorized" >< buf) return 1;
  # error message for IOS, ASA
  if ("ERROR: Command authorization failed" >< buf) return 1;
  # error message for IOS XE
  #if ((get_kb_item("Host/Cisco/IOS-XE") && ("" >< buf)) return 1;
  # error message for NX-OS
  #if ((get_kb_item("Host/Cisco/NX-OS") && ("" >< buf)) return 1;
  # error message for IPS
  #if ((get_kb_item("Host/Cisco/IPS") && ("" >< buf)) return 1;
  # error message for WLC
  #if ((get_kb_item("Host/Cisco/WLC") && ("" >< buf)) return 1;
  # error message for NAM
  #if ((get_kb_item("Host/Cisco/NAM") && ("" >< buf)) return 1;
  # error message for CNU-OS
  #if ((get_kb_item("Host/Cisco/CNU-OS") && ("" >< buf)) return 1;
  # error message for CUC
  #if ((get_kb_item("Host/Cisco/CUC") && ("" >< buf)) return 1;

  # Check the command prompt to see if 'enable' was successful.
  prompt = get_kb_item("/tmp/ssh_cmd/cmd_prompt");
  if (
    !isnull(prompt) && 
    ereg(pattern:"#[ \t]*$", string:prompt)
  ) return 0;

  if ("% Invalid input detected at " >< buf ) return 1;

  return 0;
}

##
# Determines if the buf returned is an error or a valid result
#
# @return 1 is good, 0 if bad/error
##
function check_cisco_result()
{
  local_var buf;
  buf = _FCT_ANON_ARGS[0];

  if (!buf) return 0;
  if (cisco_needs_enable(buf)) return 0;
  if ("% This command is not authorized" >< buf) return 0;
  if ("% Invalid input" >< buf) return 0;
  if ("ERROR: " >< buf) return 0;

  return 1;
}

##
# Checks to see if the requested kb_item exists.
#         If so, simply return the kb_item.
#         If not, then collect the data and set the kb_item.
#
# @anonparam kb_item The kb_item to check
#
# @anonparam cmd The cmd to gather the kb_item info
#
# @anonparam flag The flag to indicate whether or not to exit on unknown error
#                 1 = exit, 0 = continue as normal
#
# @return the value stored in the kb_item or gathered via
#         the cmd, or
#         NULL if there were any errors
##
function cisco_command_kb_item()
{
  local_var kb_item, cmd;
  local_var buf;
  local_var flag;

  # get parameters
  kb_item = "Secret/"+_FCT_ANON_ARGS[0];
  cmd = _FCT_ANON_ARGS[1];
  flag = 0;
  if ( _FCT_ANON_ARGS[2] ) flag = _FCT_ANON_ARGS[2];

  # if no kb_item is specified, return
  if (!kb_item)
    return NULL;

  # immediately return the command output if we already know it
  buf = get_kb_item(kb_item);
  if (buf)
  {
    return buf;
  }

  # if no command is specified, return
  if (!cmd)
    return NULL;

  # setup ssh tunnel
  sock_g = ssh_open_connection();
  if (! sock_g) exit(1, "ssh_open_connection() failed.");

  # issue command
  buf = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, cisco:TRUE);
  ssh_close_connection();

  if (buf) 
  {
    # set kb item for future use
    set_kb_item(name:kb_item , value:buf );
  }
  if (buf && flag && !cisco_needs_enable(buf))
    exit(1, 'ERROR executing ['+cmd+'] = '+substr(buf,0,160));
  return buf;
}

##
# Examines sections of the Cisco running-config for the specified regular
# expression by using '!' as the default delimiter.
#
# @param string      config        'show running-config' or similar output 
# @param string      section_regex section(s) to look for via a PCRE   
# @param list|string config_regex  list of configs or single config to look for via PCREs
# @param string      delimiter     OPTIONAL end boundary for the section (default: '!')
#
# @return TRUE  if all config_regex(es) are found in the section(s) found by
#               using section_regex
#         FALSE otherwise
##
function cisco_check_sections(config, section_regex, config_regex, delimiter)
{
  local_var matches, match, found, config_regexes;
  local_var str, idx_end;

  if (empty_or_null(config))
  {
    err_print("cisco_check_sections: 'config' must be specified.");
    exit(1);
  }

  if (empty_or_null(section_regex))
  {
    err_print("cisco_check_sections: 'section_regex' must be specified.");
    exit(1);
  }

  if (empty_or_null(config_regex))
  {
    err_print("cisco_check_sections: 'config_regex' must be specified.");
    exit(1);
  }

  # Make a list always
  config_regexes = config_regex;
  if (typeof(config_regexes) != 'array')
    config_regexes = make_list(config_regexes);


  if (isnull(delimiter)) delimiter = "!";

  matches = egrep(pattern:section_regex, string:config);
  if (!empty_or_null(matches))
  {
    matches = split(matches, keep:FALSE);
    foreach match (matches)
    {
      found = 0;
      str = strstr(config, match);
      idx_end = stridx(str, delimiter);
      str = substr(str, 0, idx_end);

      foreach config_regex (config_regexes)
      {
        if (preg(string:str, pattern:config_regex, multiline:TRUE))
          found++;
      }

      if (found == len(config_regexes))
        return TRUE;
    }
  }
  return FALSE;
}
