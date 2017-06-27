#TRUSTED 999834ed6e2708f28c989732875e53ede98a6617948b4e6fe6a10be803f54f421aa2528b15573f822c92a68d16e2afd6d38fe25286c567a2406421ed3000f2645f617404d1576b22285449c6fd275f40b498049d9aaeccba1971a4a1e2e33efadc52e734796b811b598d7bc5fc8dcdd5acd432e26dfb0d3200588881550370df19cf4b3e79f79576564fbd3ad0a4710479878f7b8c697bb12ca76ea05da27fd9d33c4b0a1f8df9e222b5525b015a4520b755c494cdf4fe4110d27ae952cfa862916e2976cdc487f026a22a855f2d1d1ae617f63a97bca7c5be01bb090ce54148f0b356ae7baca17228ac7bd0240393943aa5f68438cc432a7a2515ffc8c8b00a4c06d7ecf9c6065a61e261e04091cd1de5e68667f0ee6adaee1f07898f6c9d3b24724014b0cf616084fb72c6492feaa85c20d33e2efbab7139082095fdaffef59fdd42d5b2370b08a8fd3365fe6b43f0b24c287fd97a241b1a320d730ed2f19b60d65bafca27788ce0d4e4be8893de739fab012db26f627415603503b18fbcb23e1aded16c6acb8632317eca1b38339b7f39fca36cd511f2df27e377f9d3a7fab4c6d8c6b25ae39e4b2e12084f18af32d499bc67fdb284d2337175ac82a0c317396462d476bc5ac08349bc6df86cc2d8de35820dea76d0ae223e511b7be3ab7c62059b0d75602c97be5b6883147e3a94b16ef4f73305c8676ec25a2a2431e2bf
#
# (C) Tenable Network Security, Inc.
#
# v1.36

global_var	experimental_scripts, report_verbosity, debug_level, thorough_tests, report_paranoia, supplied_logins_only;

experimental_scripts = 0;
report_verbosity = 1;
debug_level = 0;
thorough_tests = 0;
report_paranoia = 1;
all_addr_private = 0;
all_addr_public = 0;
supplied_logins_only = 0;

SECURITY_HOLE    = 'Hole';
SECURITY_WARNING = 'Warning';
SECURITY_NOTE    = 'Note';

if (  get_kb_item("global_settings/supplied_logins_only") ) 
{
 supplied_logins_only = 1;
}

__gs_opt = get_kb_item("global_settings/network_type");
if (__gs_opt)
{
  if ("LAN" >< __gs_opt) all_addr_private = 1;
  else if ("Internet" >< __gs_opt) all_addr_public = 1;
}

__gs_opt = get_kb_item("global_settings/report_verbosity");
if (__gs_opt)
{
  if ("Normal" >< __gs_opt) report_verbosity = 1;
  else if ("Quiet" >< __gs_opt) report_verbosity = 0;
  else if ("Verbose" >< __gs_opt) report_verbosity = 2;
}

__gs_opt = get_kb_item("global_settings/report_paranoia");
if (__gs_opt)
{
  if ("Avoid false alarms" >< __gs_opt) report_paranoia = 0;
  else if ("Normal" >< __gs_opt) report_paranoia = 1;
  else if ("Paranoid" >< __gs_opt) report_paranoia = 2;
}

__gs_opt = get_kb_item("global_settings/debug_level");
debug_level = int(__gs_opt);
if (debug_level < 0) debug_level = 0;

__gs_opt = get_kb_item("global_settings/experimental_scripts");
if ( __gs_opt )
{
   if ( "no" >< __gs_opt ) experimental_scripts = 0;
   else if ("yes" >< __gs_opt) experimental_scripts = 1;
}

__gs_opt = get_kb_item("global_settings/thorough_tests");
if ( __gs_opt )
{
 if ( "no" >< __gs_opt) thorough_tests = 0;
 else if ("yes" >< __gs_opt) thorough_tests = 1;
}

# a0 to a9 parameters are useless. They were added to suppress a warning
# with old NASL2 interpreters
function debug_print(level, a0, a1, a2, a3, a4, a5, a6, a7, a8, a9)
{
 local_var	msg, i, l;

 if (isnull(level)) level = 1;
 if (debug_level < level) return;
 if ( nasl_level() < 2191 ) return;
 msg = strcat(SCRIPT_NAME, '(', get_host_ip(), '): ');
 foreach i (_FCT_ANON_ARGS) { msg = string(msg, i); }
 l = strlen(msg);
 if (l == 0) return;
 if (msg[l-1] != '\n') msg += '\n';
 display("DEBUG: ", msg);
}

# Only use this function to print a fatal error, e.g. a violation of an API
function err_print(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9)
{
 local_var	msg, i, l;

 if ( nasl_level() < 2191 ) return;
 msg = strcat(SCRIPT_NAME, '(', get_host_ip(), '): ');
 foreach i (_FCT_ANON_ARGS) { msg = string(msg, i); }
 l = strlen(msg);
 if (l == 0) return;
 if (msg[l-1] != '\n') msg += '\n';
 display("ERR: ", msg);
}

##
# Taken from http_misc_func.inc
#
# @param resp       Text from our response to include in the report
# @param max_lines  Max number of lines to include of output. Default to 10
##
function beginning_of_response2(resp, max_lines)
{
  local_var     txt, i, line;

  if (isnull(resp))
    return err_print('beginning_of_response2: missing parameter resp.');

  if (max_lines <= 0) max_lines = 10;
  i = 0;
  foreach line(split(resp, keep: 0))
  {
    line = chomp(line);
    line = ereg_replace(string: line, pattern: '^[ \t]+', replace: '');
    txt += line + '\n';
    if (++ i  >= max_lines) return txt + '[...]\n';
  }
  return txt;
}

##
# security_report will appear in Nessus 5
#
# @param port       port number of the web server
# @param proto      sets the reporting protocol, defaults to tcp
# @param severity   report severity (note, warning, hole)
# @param extra      report text to display
# @param cmd        Command executed.  Used in the report output.  If TRUE
#                   use code/command execution report
# @param file       File to use in report. If TRUE, use reporting for lfi/rfi
# @param request    array list of request(s) used in report output
# @param output     Output to use in report for file_read or cmd_exec
#                   Is an optional param when generic is TRUE
# @param line_limit Number of output lines to display in report. 10 by default
# @param rep_extra  Any extra text to include in the report output (optional)
# @param attach_type Attachment type used with security_report_with_attachments
#                    defaults to 'text/plain' in none provided.
# @param generic    Used for reporting of general SQLi / XSS vulns
#                   When generic is TRUE, output can be optional
# @param sqli       If TRUE, sets SQLInjection KB item
# @param xss        If TRUE, sets XSS KB item
# @param xsrf       If TRUE, sets XSRF KB item
##
function security_report_v4(port, proto, severity, extra, cmd, file, request, output, line_limit, rep_extra, attach_type, generic, sqli, xss, xsrf)
{
  local_var attach_level, snip, s, report, rep_footer, rep_header;
  local_var num_req, attachments, i;

  if (isnull(severity))
    return err_print('security_report_v4: missing parameter severity.');
  if (isnull(port))
    return err_print('security_report_v4: missing parameter port.');

  if ( (!isnull(cmd)) || (!isnull(file)) )
  {
    if (isnull(request))
      return err_print('security_report_v4: missing parameter request.');
    if (isnull(output))
      return err_print('security_report_v4: missing parameter output.');
  }

  # validate the protocol
  if(isnull(proto) || !strlen(string(proto)))
    proto = 'tcp';
  else if(tolower(proto) !~ "^(tcp|udp|icmp|egp)$")
    proto = 'tcp';
  else
    proto = tolower(proto);

  # These are set unconditionally
  if (xss)
    replace_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (xsrf)
    replace_kb_item(name:"www/"+port+"/XSRF", value:TRUE);
  if (sqli)
    replace_kb_item(name:"www/"+port+"/SQLInjection", value:TRUE);

  attach_level = 2;  # Default value
  if (severity == SECURITY_NOTE) attach_level = 0;
  if (severity == SECURITY_WARNING) attach_level = 2;
  if (severity == SECURITY_HOLE) attach_level = 3;

  if (isnull(line_limit))
    line_limit = 10;

  if (isnull(attach_type))
    attach_type = 'text/plain';

  snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
  rep_footer = crap(data:"-", length:66);

  if (!isnull(cmd))
  {
    num_req = max_index(request);
    if (num_req > 1) s = "s";
    else s = "";

    report =
      '\nNessus was able to execute the command "' + cmd + '" using the' +
      '\nfollowing request' + s + ' :' +
      '\n' + 
      '\n';

    for (i=0; i < (num_req); i++)
    {
      if (num_req > 1)
      {
        rep_header = crap(data:"-", length:30)+' Request #' + (i + 1) +
        crap(data:"-", length:30) + '\n';
      }
      else rep_header = '';
      report += rep_header + request[i] + '\n';
    }

    if (rep_extra)
      report += '\n' + rep_extra + '\n';

    report +=
      '\n\n' + 'This produced the following truncated output (limited to ' +
      line_limit + ' lines) :' +
      '\n' + snip +
      '\n' + beginning_of_response2(resp:output, max_lines:line_limit) +
      '\n' + snip +
      '\n';

    if (severity == SECURITY_HOLE)
      security_hole(port:port, proto:proto, extra:report);
    else if (severity == SECURITY_WARNING)
      security_warning(port:port, proto:proto, extra:report);
    else
      security_note(port:port, proto:proto, extra:report);
  }

  else if (!isnull(file))
  {
    num_req = max_index(request);
    if (num_req > 1) s = "s";
    else s = "";

    report =
      '\nNessus was able to exploit the issue to retrieve the contents of ' +
      '\n' + "'" + file + "'" + ' using the following request' + s + ' :' +
      '\n' +
      '\n';

    for (i=0; i < (num_req); i++)
    {
      if (num_req > 1)
      {
        rep_header = crap(data:"-", length:30)+' Request #' + (i + 1) +
        crap(data:"-", length:30) + '\n';
      }
      else rep_header = '';
      report += rep_header + request[i] + '\n';
    }

    if (rep_extra)
      report += '\n' + rep_extra + '\n';

    if (
      !defined_func("nasl_level") ||
      nasl_level() < 5200 ||
      !isnull(get_preference("sc_version"))
    )
    {
      report +=
        '\n' + 'This produced the following truncated output (limited to ' +
        line_limit + ' lines) :' +
        '\n' + snip +
        '\n' + beginning_of_response2(resp:output, max_lines:line_limit) +
        '\n' + snip +
        '\n';

      if (severity == SECURITY_HOLE)
        security_hole(port:port, proto:proto, extra:report);
      else if (severity == SECURITY_WARNING)
        security_warning(port:port, proto:proto, extra:report);
      else
        security_note(port:port, proto:proto, extra:report);
    }
    else
    {
      # Sanitize file names
      if ("/" >< file) file = ereg_replace(
        pattern:"^.+/([^/]+)$", replace:"\1", string:file);
      if ("\" >< file) file = ereg_replace(
        pattern:"^.+\\([^\\]+)$", replace:"\1", string:file);

      report +=
        '\n' + 'Attached is a copy of the response' + '\n';
      attachments = make_list();
      attachments[0] = make_array();
      attachments[0]["type"] = attach_type;
      attachments[0]["name"] = file;
      attachments[0]["value"] = output;
      security_report_with_attachments(
        port  : port,
        level : attach_level,
        extra : report,
        attachments : attachments
      );
    }
  }

  else if (generic)
  {
    num_req = max_index(request);
    if (num_req > 1) s = "s";
    else s = "";

    report =
      '\nNessus was able to exploit the issue using the following request'
      + s + ' :\n\n';

    for (i=0; i < (num_req); i++)
    {
      if (num_req > 1)
      {
        rep_header = crap(data:"-", length:30)+' Request #' + (i + 1) +
        crap(data:"-", length:30) + '\n';
      }
      else rep_header = '';
      report += rep_header + request[i] + '\n';
    }

    if (rep_extra)
      report += '\n' + rep_extra + '\n';

    # Allow output to be optional for Generic cases.
    if (!isnull(output))
    {
      report +=
        '\n\n' + 'This produced the following truncated output (limited to ' +
        line_limit + ' lines) :' +
        '\n' + snip +
        '\n' + beginning_of_response2(resp:output, max_lines:line_limit) +
        '\n' + snip +
        '\n';
    }

    if (severity == SECURITY_HOLE)
      security_hole(port:port, proto:proto, extra:report);
    else if (severity == SECURITY_WARNING)
      security_warning(port:port, proto:proto, extra:report);
    else
      security_note(port:port, proto:proto, extra:report);
  }

  else if (report_verbosity < 1 || isnull(extra))
  {
    if (severity == SECURITY_HOLE)
      security_hole(port:port, proto:proto);
    else if (severity == SECURITY_WARNING)
      security_warning(port:port, proto:proto);
    else
      security_note(port:port, proto:proto);
  }
  else
  {
    if (severity == SECURITY_HOLE)
      security_hole(port:port, proto:proto, extra:extra);
    else if (severity == SECURITY_WARNING)
      security_warning(port:port, proto:proto, extra:extra);
    else
      security_note(port:port, proto:proto, extra:extra);
  }
}

GLOBAL_SETTINGS_INC = 1;
