#TRUSTED b087fee3dbee03c98a9d17d94ff23b44403ae5055fb5e8b3a9fbdf45e11b0d005bee9de438d71421141ff57f73bdc80e275c6158eb698f73ba0848b14206a54378491b9051a0736d5ea790c1c4d92f6af30d5617d67e56fbe41dc95e37d6976f236b7f3e17e6b4dc146355dd7c01c35bc9522f2f615b452f8162af500643983d6b1d5275879528e8d434875c3465e71f5e71291098770dd373cdae7be1119ae9cb5867d9a8bffa5cec00c9355a3d947105e349f64eb784ef07644a7c05e1f476da0484d5a1e07f800c457fa31d66fa3b0830fc9cd8286e8c4c1bf18e0164454b9cb6bcf72f41ea448c3a54d2079aa3d08bb39ae4c413b8f181e8183f84531472c076c86e71b2a8fa52af0506b1756f5f60dc4e3e333e365574b2b53b2f571f81c0d53a456df749264c701c08b3d162f7793c01920167313b056b1744e36fadd4cc5effd8894a57d00d7abf2fedd85a2bac9e7cb2f764fe1e1ddf5a08826607ebc57e9ff169c996941532a25ed4f6631cc01a50736b97067661b0429123338b54bcd11f11f77b412959392a8cfc7e7a4280a70bf8fdd75e4a106c6b3265b21063dd02aadaac7722c6e7ef7a71be17652eaacfaf442029dcde4b7f4493718a2b60ff2d57e060251d26608b817af3446aedc9b909cc94c18a06f0a2e0d4c799d8cdc4efa5bc5afe3337ed4ef56ffae7ff1b745cd1f86915ab5cad469470f2b5be44
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision: 1.1
###

include("junos.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

##
# Determines if the output returned is an error or a valid result
#
# @return TRUE  if the output appears valid
#         FALSE if the output appears to be an error or invalid
##
function junos_check_result()
{
  local_var buf;
  buf = _FCT_ANON_ARGS[0];

  if (isnull(buf)) return FALSE;
  if ("syntax error, expecting <command>" >< buf) return FALSE;
  if ("unknown command" >< buf) return FALSE;

  return TRUE;
}

##
# Checks if the statement is deactivated or disabled
#
# @param string  buf       return buffer from Junos command
# @param string  pattern   to check for configuration
# @param boolean multiline OPTIONAL pass to preg (default: TRUE) 
#
# @return TRUE  if the configuration is enabled
#         FALSE if the configuration is not found or disabled
##
function junos_check_config(buf, pattern, multiline)
{
  local_var statements, lines, line;
  local_var deactivate_pat, disable_pat, matches;

  if (isnull(pattern))
  {
    err_print("junos_check_config: 'pattern' must be specified");
    exit(1);
  }

  if (isnull(multiline)) multiline = TRUE;

  statements = pgrep(string:buf, pattern:pattern);
  if (statements == '')
    return FALSE;

  lines = split(statements, sep:'\n', keep:FALSE);
  foreach line (lines)
  {
    # Look for deactivated statement in the config
    deactivate_pat = str_replace(string:line, find:"set", replace:"deactivate", count:1);
    if (preg(string:buf, pattern:deactivate_pat, multiline:TRUE)) continue;

    # Look for disable statement in the matching statements
    if (line =~ " disable$") continue;

    disable_pat = "^" + line +  " disable$";
    if (preg(string:statements, pattern:disable_pat, multiline:TRUE)) continue;

    return TRUE; # Statement was found not deactivated or disabled
  }

  return FALSE;
}

##
# Checks if the specified KB item exists.
#   If it does, simply return the output stored in the KB item.
#   If it doesn't, execute the specified command and store the output in the KB item.
#
# @param string  cmd the command to gather the KB item info
#
# @param string  kb      OPTIONAL KB item to check
# @param boolean no_more OPTIONAL do not paginate command output (default: TRUE)
#
# @remark 'kb' should only be specified for commands with special characters or
#         where the KB deviates from the command in some way
#
# @return output from executed command
#         FALSE  if local checks is not enabled
#         NULL   if there were any errors
##
function junos_command_kb_item(cmd, kb, no_more)
{
  local_var shell, buf;

  if (!get_kb_item("Host/local_checks_enabled")) return FALSE;

  if (isnull(cmd))
  {
    err_print("junos_command_kb_item: 'cmd' must be specified");
    exit(1);
  }

  shell = get_kb_item("Host/Juniper/JUNOS/shell");

  if (isnull(no_more)) no_more = TRUE;

  # Replace whitespaces with underscores and remove forward slashes for KB
  if (isnull(kb))
  {
    kb = str_replace(string:cmd, find:" ", replace:"_");
    kb = str_replace(string:kb, find:"/", replace:"");
    kb = "Host/Juniper/JUNOS/Config/" + kb;
  }
  # Add the 'no-more' display filter to not use pagination (enabled by default) 
  if (no_more && "| no-more" >!< cmd)
    cmd += " | no-more";

  # Return the command output if we already know it
  buf = get_kb_item("Secret/"+kb);
  if (!isnull(buf)) return buf;

  
  # Issue specified command
  if (shell)
  {
    if (islocalhost())
    {
      if (!defined_func("pread")) exit(1, "'pread()' is not defined.");
      info_t = INFO_LOCAL;
    }
    else
    {
      info_t = INFO_SSH;
      if (!ssh_open_connection()) exit(1, "Failed to open an SSH connection.");
    }

    if ("|" >< cmd) cmd = str_replace(string:cmd, find:"|", replace:"\|");
    buf = info_send_cmd(cmd:'cli ' + cmd);
    if (info_t == INFO_SSH) ssh_close_connection();
  }
  else
  {
    if (!ssh_open_connection()) exit(1, "Failed to open an SSH connection.");
    buf = ssh_cmd(cmd:cmd + '\r\n', nosudo:TRUE, nosh:TRUE);
    ssh_close_connection();
  }

  if (junos_check_result(buf))
  {
    set_kb_item(name:"Secret/"+kb, value:buf); # set KB item for future use
    return buf;
  }
  else return NULL;
}

##
# Returns a message that the configuration was not checked
#
# @anonparam TRUE  if configuration was not checked
#            FALSE if configuration was checked
# @param     boolean display generic caveat message (no reason in message)
# @return NULL if local checks are enabled and FALSE is passed
#         caveat string if local checks are not enabled or TRUE is passed
##
function junos_caveat(generic)
{
  # Configuration was checked
  if (get_kb_item("Host/local_checks_enabled") && !_FCT_ANON_ARGS[0]) return NULL;

  # Generic message
  if (!isnull(generic) && generic)
    return
      '\nNote that Nessus has not tested for this issue or the host ' +
      '\nconfiguration instead it has instead relied only on the ' +
      '\napplication\'s self-reported version number.\n';

  # Configuration was not checked because...
  #  local checks are not enabled
  if (!get_kb_item("Host/local_checks_enabled"))
    return
      '\nNote that Nessus has not tested for this issue or the host ' +
      '\nconfiguration because local checks are not enabled. Instead, ' +
      '\nNessus has relied only on the application\'s self-reported ' +
      '\nversion number.\n';
  #  an error occurred
  else
    return
      '\nNote that Nessus has not tested for this issue or the host ' +
      '\nconfiguration because an error occurred while attempting to test. ' +
      '\nInstead, Nessus has relied only on the application\'s self-reported ' +
      '\nversion number.\n';
}

##
# Reports and, if relevant, sets PCI KB(s) and include caveat message in report
#
# @param ver      string  installed version
# @param fix      string  fixed version
# @param override boolean display caveat message
# @param severity integer report severity SECURITY_(NOTE, WARNING, HOLE)
# @param model    string  OPTIONAL detected model
# @param xss      boolean OPTIONAL set XSS KB item
# @param xsrf     boolean OPTIONAL set XSRF KB item
# @param sqli     boolean OPTIONAL set SQLi KB item
#
# @return This function has no return values
##
function junos_report(ver, fix, override, severity, model, xss, xsrf, sqli)
{
  local_var port, extra;

  port = 0;  
  extra = NULL;

  if (xss)  set_kb_item(name:'www/0/XSS', value:TRUE);
  if (xsrf) set_kb_item(name:'www/0/XSRF', value:TRUE);
  if (sqli) set_kb_item(name:'www/0/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
    extra = get_report(ver:ver, fix:fix, model:model) + junos_caveat(override);
  else
    extra = junos_caveat(override);

  security_report_v4(port:port, extra:extra, severity:severity);
}
