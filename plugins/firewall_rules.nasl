#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56310);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/06/02 17:53:33 $");

  script_name(english:"Firewall Rule Enumeration");
  script_summary(english:"Enumerates firewall rules");

  script_set_attribute(
    attribute:"synopsis",
    value:"A firewall is configured on the remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Using the supplied credentials, Nessus was able to get a list of
firewall rules from the remote host."
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/28");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "wmi_enum_firewall_rules.nbin");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

##
# Strips any empty chains from the given iptables output.
#
# @anonparam output iptables output to strip
# @return 'output', minus any empty chains.
#         if no empty chains were found, 'output' is returned.
#         if only empty chains were found, NULL is returned.
##
function iptables_strip_empty_chains()
{
  local_var output, line, lines, stripped_output, chain, rules, stripped;
  output = _FCT_ANON_ARGS[0];
  lines = split(output, sep:'\n', keep:FALSE);

  stripped_output = NULL;
  chain = NULL;
  rules = -1;  # start at -1 to ignore the initial header line ("pkts bytes target...")
  stripped = FALSE;

  # go through the output line by line, rebuilding the rules for each chain.
  # if there are no rules, scrap the chain. otherwise, added to the new output
  foreach line (lines)
  {
    # beginning section for a chain
    if (line =~ '^Chain ')
    {
      if (rules > 0)  # add the previous (non-empty) chain to the final output
        stripped_output += chain;
      else if (!isnull(chain)) # the previous chain was empty, don't add it to the report
        stripped = TRUE;

      chain = line + '\n';
      rules = -1;
    }
    else
    {
      # add this line to the section for the current chain...
      chain += line + '\n';

      # don't count this line as a rule if it's blank
      if (line != '')
        rules++;
    }
  }

  # account for the last chain in the output
  if (rules > 0)
    stripped_output += chain;

  # give the user a heads up so they know we're not reporting iptables output verbatim
  if (!isnull(stripped_output) && stripped)
    stripped_output +=
'\nPlease note this table has at least one empty chain which was not
included in the output above.\n';

  return stripped_output;
}

##
# Reformats command output to make it more suitable for the report
#
# @anonparam cmd    command executed to get firewall rules
# @anonparam output output received by running "cmd"
# @return reformatted 'output' if any reformatting was needed,
#         'output' if no reformatting was needed
##
function reformat()
{
  local_var cmd, output;
  cmd = _FCT_ANON_ARGS[0];
  output = _FCT_ANON_ARGS[1];

  if (cmd =~ '^iptables')
    return iptables_strip_empty_chains(output);
  else
    return output;
}

rules = get_kb_list('Host/fwrules/output/*');
if (isnull(rules))
{
  errmsgs = get_kb_list('Host/fwrules/errmsg/*');
  if (!isnull(errmsgs))
  {
    errors = make_array();
    expected_errors = TRUE;
    foreach msg (errmsgs)
    {
      msg = chomp(msg);
      if('failed to produce any results for some reason' >!< msg)
        expected_errors = FALSE;
      errors[msg]++;
    }
    if (max_index(keys(errors)) == 1) s = ' was';
    else s = 's were';

    if(!expected_errors)
      exit(1, 'The following error'+s+' encountered while trying to list firewall rules :\n\n  ' + join(sep:'\n  ', keys(errors)) + '\n');
  }
  exit(0, 'No "Host/fwrules/*" KB keys were found.');
}

report = '';
info = '';
foreach key (keys(rules))
{
  cmd = key - 'Host/fwrules/output/';
  list = reformat(cmd, rules[key]);
  if (isnull(list) || !list) continue;

  if ('netsh' >< cmd)
  {
    profiles = get_kb_list('Host/fwrules/netsh/*/enabled');
    foreach key (keys(profiles))
    {
      profile = key - 'Host/fwrules/netsh/';
      profile -= '/enabled';
      if (profile == 'std') profile = 'Standard';
      else if (profile == 'dom') profile = 'Domain';
      else if (profile == 'pub') profile = 'Public';

      if (profiles[key])
      {
        info += profile + '\n';
      }
    }
  }
  report +=
    '\nBy running "' + cmd + '", Nessus was able to get the ' +
    '\nfollowing list of firewall rules :\n\n' +
    list;

  if ('netsh' >< cmd)
  {
    if (info) 
      report = '\nThe following Firewall profiles are enabled on the remote Windows host:\n' +
                '  ' + info +
                report;
    else
      report = '\nNote that the Windows Firewall is disabled.\n' +
               report;
  }
}

if (!report) exit(1, 'Failed to generate a report.');
else security_note(port:0, extra:report);
