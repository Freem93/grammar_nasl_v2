#TRUSTED 348ff2f49c22f19fb12910c29f8538928ede60a4a32c8d895e1eac4d75a147256c2c73b9ef3b571b0a33bbcf5db4b58ecafc3f548076ca7e40ba0c7f2ea091874b6ebdacc1704a306505b250efaed7cff2d2dedff6da1d50382eb64b2a80b954c0b41c20894ee1dfc3c59198ea1c569c15cfdcf5b4f332fb7b104f196650ee4de6a6f53aa9be15b7543e27597a2ee18348e3a36c40cec803a6257c0214c3429fc863b21bdb73dac0d934a2be9dd73e0dde4538978f75fecf3410ebeb04b451f09d2ae4aa8370cea9c19407a7e226c90dac60c2af7cc37f23354c708e60d58c93783219b27aaf56fe5288ebe198f8e6bdac7add0be34f5cc9a592de45b4cb0c3d17bd5186c73733f7740a64be153f773e9e16537967418280c0fbefca8e7444865591e8df7b9a864a67b4f3c4206b15fc5e7ac8ce59fcfce461b30c751449ad6644825ec44e2f51da48a497e8d7569e298075d7d2e598c098cee3ef14bc6070834bcdb85b78f113fd8d8e38fa8a417395418b2853950a93205d3aeed141fd96fcb3fb6b35a3c7a3d83570fe94ada1eeb2ff913867b53dd52162c0f9c438652ddc9d240e82eb0694a2e563e7c337c6ed28dc50b45c56cabdad7db6139a5602a6f0be2f3b4977ea792966dd0100d30b5582f7dca528d9cc6f5c572d72d20b3866ccc43c3b52074c399f3b905fb246c13f899c2d79377f7dfb45488cf74a470a2dae
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# vcf.inc
#
# Revision: 1.3

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

namespace vcf
{
  TAP = 0;
  DEBUG = 0;
  function dbg() { if (vcf::DEBUG) display(_FCT_ANON_ARGS[0] + '\n'); }

  ####################
  # Parser variables #
  ####################

  # Pre-release conversion values
  var conversions = { "rc" : -50, "beta" : -75, "alpha" : -100 };

  ##
  # Add values to the conversion array. This also overwrites existing conversion values.
  #
  # @anonparam   1st   array of intended additions
  ##
  function add_conversions() # Pass this an array of intended additions
  {
    local_var conversion, additions;
    additions = _FCT_ANON_ARGS[0];
    foreach conversion (keys(additions))
      conversions[conversion] = additions[conversion];
  }

  # Valid version segment separators
  var separators = ['.'];

  ##
  # Add values to the separators list
  #
  # @anonparam   1st   list of separators to include
  ##
  function add_separator() { separators[max_index(separators)] = _FCT_ANON_ARGS[0]; }

  ##################
  # Error handling #
  ##################
  # NOTE: Top level functions in this framework (those called by plugins) will
  #       exit upon error

  # Used when storing errors in the KB
  # This might limit some back-and-forth with customers in the future
  ERROR_ID = 0;

  ##
  # Saves the error to the KB. Also calls display() if debugging enabled
  #
  # @anonparam   1st   Error message
  ##
  function print_error()
  {
    dbg(_FCT_ANON_ARGS[0]);
    set_kb_item(name:"Errors/" + SCRIPT_NAME + "/" + string(ERROR_ID++), value:_FCT_ANON_ARGS[0]);
  }

  # Dedicated error type
  object Error
  {
    var message = "An unknown error occurred.";
    function Error()
    {
      this.message = _FCT_ANON_ARGS[0];
      print_error(message);
    }
  }

  ##
  # Standardized message for a parsing error
  #
  # @param   str      string that caused the error
  # @param   index    index being parsed when error occurred
  # @param   msg      additional information
  #
  # @return  An error object
  ##
  function parse_error(str, index, msg)
  {
    return new('vcf::Error', 'Error parsing version: "' + str + '" at index: ' + index + ': ' + msg);
  }

  ##
  # Standardized message for a missing or invalid argument
  #
  # @param   arg    The missing or invalid argument
  # @param   func   The function the error occurred in
  #
  # @return  An Error object
  #
  # @remark "func" will generally be passed FUNCTION_NAME, which indicates the calling function
  ##
  function arg_error(arg, func)
  {
    return new("vcf::Error", "Missing or invalid '" + arg + "' argument in call to '" + func + "'.");
  }

  ##
  # Determines if the passed variable is an Error
  #
  # @anonparam   1st   variable to check
  #
  # @return TRUE/FALSE
  ##
  function is_error() { return (typeof_ex(_FCT_ANON_ARGS[0]) == 'vcf::Error'); }

  #####################
  # Primary Functions #
  #####################

  ##
  # Calls both check_version() and report_results()
  #
  # @param app_info    array containing application info. requires, at minimum, a
  #                    key/value pair for 'version'
  # @param constraints list of constraint arrays
  # @param severity    severity used in reporting
  # @param strict      bool that determines whether or not version/fix should
  #                    require the same number of fields
  # @param flags       array of reporting flags (xss, sqli, xsrf)
  #
  # @remark This function exits.
  ##
  function check_version_and_report(app_info, constraints, severity, strict, flags)
  {
    local_var matching_constraint, fix, report_ver;

    if (isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
    if (isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);
    if (isnull(constraints)) return arg_error(arg:"constraints", func:FUNCTION_NAME);

    matching_constraint = check_version(version:app_info.parsed_version, constraints:constraints, strict:strict);
    if (is_error(matching_constraint)) return vcf_exit(1, matching_constraint.message);

    if (!isnull(matching_constraint))
    {
      fix = matching_constraint.fixed_display;
      if (isnull(fix)) fix = matching_constraint.fixed_version;

      report_results(app_info:app_info, fix:fix, severity:severity, flags:flags);
    }
    # Audit
    else return audit(app_info);

    return vcf_exit(0);
  }

  ##
  # Obtains information for the given application. If provided with
  # just an app name, get_single_install() will be used. KB paths
  # will override the default behavior.
  #
  # @param app         application name
  # @param port        port to check for application with
  # @param kb_ver      kb path to use to obtain version information
  # @param kb_backport kb path to use to obtain backport information
  # @param win_local   sets port to 445 after obtaining version info
  # @param webapp      sets a value in app_info to determine path report output later
  # @param service     sets a value in app_info that affects audit messages
  # @param proto       protocol to use for reporting/audit outputs
  #
  # @return array with relevant application info, typically version
  #         information, path information, a preferred display variant
  #         of the version, etc.
  #
  # @remark This function can exit when a backported kb path is supplied
  ##
  function get_app_info(app, port, kb_ver, kb_backport, kb_source,  win_local, webapp, service, proto)
  {
    local_var install = {};
    local_var win_port, parsed_version;

    if (isnull(app)) return arg_error(arg:"app", func:FUNCTION_NAME);

    # Check against backported software
    if (!isnull(kb_backport))
    {
      local_var backported = get_kb_item_or_exit(kb_backport, exit_code:1);
      if (report_paranoia < 2 && backported) ::audit(AUDIT_BACKPORT_SERVICE, port, app);
    }

    // If a kb value containing version information is not supplied,
    // default to using get_single_install()
    if (isnull(kb_ver))
    {
      if (port)
      {
        install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);
        install.port = port;
      }
      else
      {
        install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
        if (win_local)
        {
          win_port = get_kb_item("SMB/transport");
          if (!win_port) install.port = 445;
          else install.port = win_port;
        }
      }
    }
    else
    {
      install.version = get_kb_item_or_exit(kb_ver);
      if (port) install.port = port;
    }

    if (kb_source) install.source = get_kb_item_or_exit(kb_source);
    if (webapp) install.webapp = TRUE;
    if (service) install.service = TRUE;
    if (proto) install.proto = proto;

    # Go ahead and parse the app's version here and store it
    parsed_version = parse_version(install.version);
    if (is_error(parsed_version)) return vcf_exit(1, parsed_version.message);

    install.parsed_version = parsed_version;

    install.app = app;
    return install;
  }

  ##
  # Check that the given version contains the appropriate
  # number of segments. Audit if necessary.
  #
  # @param  app_info      the associated app_info array
  # @param  sig_segments  minimum number of segments the version should have
  #
  # @return NULL. Exits when appropriate.
  ##
  function check_granularity(app_info, sig_segments)
  {
    if (isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
    if (isnull(sig_segments)) return arg_error(arg:"sig_segments", func:FUNCTION_NAME);

    local_var num_segments = 0;
    local_var segment;

    # Increment sig_segments to account for default length of pre-release segment
    if (app_info.parsed_version[1][0] == 0) sig_segments++;

    foreach segment (app_info.parsed_version)
      num_segments += max_index(segment);

    if (num_segments < sig_segments)
    {
      if (TAP) return vcf_exit(0);
      else ::audit(AUDIT_VER_NOT_GRANULAR, app_info.app, app_info.port, app_info.version);
    }
  }


  #############
  # Reporting #
  #############

  ##
  # Call security_report_v4() with given severity and flags
  #
  # @param app_info app info to use in report
  # @param fix      the fixed version to include in report
  # @param severity SECURITY_(NOTE|HOLE|WARNING)
  # @param flags    xss, xsrf, and sqli
  # @param webapp   converts path to a URL
  #
  # @return NULL
  ##
  function report_results(app_info, fix, severity, flags)
  {
    local_var report, version, port;

    if (isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);
    if (isnull(fix)) return arg_error(arg:"fix", func:FUNCTION_NAME);
    if (isnull(severity)) return arg_error(arg:"severity", func:FUNCTION_NAME);

    if (isnull(app_info.display_version)) version = app_info.version;
    else version = app_info.display_version;

    report = build_report(version:version, fix:fix, path:app_info.path, source:app_info.source, webapp:app_info.webapp, port:app_info.port);
    if (is_error(report)) return vcf_exit(1, report.message);

    port = app_info.port;
    if (isnull(port)) port = 0;

    security_report_v4(severity:severity, port:port, extra:report, xss:flags.xss, xsrf:flags.xsrf, sqli:flags.sqli, proto:app_info.proto);
    return vcf_exit(0);
  }

  ##
  # Builds the report used in reporting output
  #
  # @param version reports as "Installed version"
  # @param path    reports as "Path" or "URL" (dep on webapp flag)
  # @param fix     reports as "Fixed version"
  # @param webapp  TRUE/FALSE (or NULL) to determine path format
  # @param port    Only used when building URLs
  # @param source  reports as "Source"
  #
  # @return The appropriate report string (extra)
  ##
  function build_report(version, path, fix, webapp, port, source)
  {
    local_var order, report, report_items;

    report_items = {
      "Installed version" : version,
      "Fixed version" : fix
    };
    order = ["Installed version", "Fixed version"];

    if (!isnull(path))
    {
      if (webapp)
      {
        if (isnull(port)) return arg_error(arg:"port", func:FUNCTION_NAME);
        report_items["URL"] = build_url2(qs:path, port:port);
        order = ["URL", "Installed version", "Fixed version"];
      }
      else
      {
        report_items["Path"] = path;
        order = ["Path", "Installed version", "Fixed version"];
      }
    }
    else if (source)
    {
      report_items["Source"] = source;
      order = ["Source", "Installed version", "Fixed version"];
    }

    return report_items_str(report_items:report_items, ordered_fields:order);
  }

  ##
  # Calls the global audit function with the appropriate audit trail
  #
  # @anonparam   1st   The app_info variable we're dealing with
  #
  # @remark This function exits
  ##
  function audit()
  {
    local_var app_info = _FCT_ANON_ARGS[0];

    if (TAP) return vcf_exit(0);

    if (app_info.app && app_info.version)
    {
      if (!isnull(app_info.path))
      {
        if (app_info.webapp)
          ::audit(AUDIT_WEB_APP_NOT_AFFECTED, app_info.app, build_url2(qs:app_info.path, port:app_info.port), app_info.version);
        else
          ::audit(AUDIT_INST_PATH_NOT_VULN, app_info.app, app_info.version, app_info.path);
      }
      else if (app_info.service)
      {
        if (!isnull(app_info.proto)) ::audit(AUDIT_LISTEN_NOT_VULN, app_info.app, app_info.port, app_info.version, app_info.proto);
        else ::audit(AUDIT_LISTEN_NOT_VULN, app_info.app, app_info.port, app_info.version);
      }
      else ::audit(AUDIT_INST_VER_NOT_VULN, app_info.app, app_info.version);
    }
    else ::audit(AUDIT_HOST_NOT, "affected");
  }

  ###################################
  # Version checking and comparison #
  ###################################

  ##
  # Used to check whether or not an application
  # version meets any of the given constraints
  #
  # @param  version       version to be checked against constraints (already parsed)
  # @param  constraints   a list of constraint arrays
  # @param  strict        if set, versions MUST have the same number of fields (segments)
  #
  # @return a matching constraint
  #         Error object
  #         NULL - no matching constraints
  #
  # @remark Possible constraint values:
  #  min_version - operates as >=
  #  max_version - operates as <=
  #  fixed_version - operates as <
  #  equal - operates as ==. no other checks performed within this same constraint
  #  fixed_display purely a display value and nothing more
  ##
  function check_version(version, constraints, strict)
  {
    local_var meets_constraint, constraint;

    if (isnull(version) || typeof(version) != "array") return arg_error(arg:"version", func:FUNCTION_NAME);
    if (isnull(constraints)) return arg_error(arg:"constraints", func:FUNCTION_NAME);
    if (isnull(strict)) strict = FALSE;

    foreach constraint (constraints)
    {
      meets_constraint = check_version_against_constraint(version:version, constraint:constraint, strict:strict);
      if (is_error(meets_constraint)) return meets_constraint;

      if (meets_constraint) return constraint;
    }

    return NULL;
  }

  ##
  # Determines whether or not the provided version falls within the
  # given constraint or not
  # 
  # @param version    Version being checked
  # @param constraint Array with possible key/values for equal,
  #                   min_version, max_version, fixed_version
  # @param strict     Bool that determines strictness of check
  #
  # @return TRUE if version within constraint
  #         FALSE otherwise
  #         Error if an error occurred
  ##
  function check_version_against_constraint(version, constraint, strict)
  {
    local_var cmp_result;

    # If an equality check is specified, nothing else is taken
    # into account. Check for an exact match.
    if (constraint.equal)
    {
      return compare_version_to_check(version:version, comparator:'=', cmp_ver:constraint.equal, strict:strict);
    }

    # Check that we meet a minimum version (if specified)
    if (constraint.min_version)
    {
      cmp_result = compare_version_to_check(version:version, comparator:'>=', cmp_ver:constraint.min_version, strict:strict);
      if (is_error(cmp_result)) return cmp_result;

      if (!cmp_result) return FALSE;
    }

    # Check that we don't exceed maximum version (if specified)
    if (constraint.max_version)
      return compare_version_to_check(version:version, comparator:'<=', cmp_ver:constraint.max_version, strict:strict);
    # Check that we're below the fixed version
    else if (constraint.fixed_version)
      return compare_version_to_check(version:version, comparator:'<', cmp_ver:constraint.fixed_version, strict:strict);

    # If we've made it this far, all of the above constraints were met
    return TRUE;
  }

  ##
  # Do comparison and check if given condition is met
  #
  # @param version    Version being checked (already parsed)
  # @param comparator Operator being used for comparison (<, <=, >, >=, =)
  # @param cmp_ver    Version being compared to
  # @param strict     Bool determining strictness of check
  #
  # @return TRUE/FALSE/Error
  ##
  function compare_version_to_check(version, comparator, cmp_ver, strict)
  {
    local_var comparison_result, i, seg, lengths_differ, pad_result, tmp_v, tmp_c;

    if (isnull(version)) return arg_error(arg:'version', func:FUNCTION_NAME);
    if (isnull(comparator)) return arg_error(arg:'comparator', func:FUNCTION_NAME);
    if (isnull(cmp_ver)) return arg_error(arg:'cmp_ver', func:FUNCTION_NAME);

    cmp_ver = parse_version(cmp_ver);
    if (is_error(cmp_ver)) return cmp_ver;

    lengths_differ = version_lengths_differ(version, cmp_ver);

    # If strict and lengths don't match, constraint is not met
    if (strict && lengths_differ)
      return FALSE;

    # Pad version segments as needed
    if (lengths_differ)
    {
      for (i=0; i<max_index(version); i++)
      {
        tmp_v = version[i];
        tmp_c = cmp_ver[i];

        pad_result = pad_segments(a:tmp_v, b:tmp_c);
        if (is_error(pad_result)) return pad_result;

        version[i] = tmp_v;
        cmp_ver[i] = tmp_c;
      }
    }

    # Compare version segments (release and pre-release segments)
    # in order.
    for (i=0; i<max_index(version); i++)
    {
      for (seg=0; seg<max_index(version[i]); seg++)
      {
        comparison_result = compare_version_segments(version[i][seg], cmp_ver[i][seg]);
        if (comparison_result != 0) break;
      }
      if (comparison_result != 0) break;
    }

    switch (comparator)
    {
      case '=':
        return comparison_result == 0;
      case '<':
        return comparison_result < 0;
      case '>':
        return comparison_result > 0;
      case '<=':
        return comparison_result <= 0;
      case '>=':
        return comparison_result >= 0;
      default:
        return new("vcf::Error", "An invalid comparator '" + comparator + "' was passed to " + FUNCTION_NAME + ".");
    }
  }

  ##
  # Check if the length of the given [parsed] versions differ
  #
  # @anonparam   1st   1st version (parsed)
  # @anonparam   2nd   2nd version (parsed)
  #
  # return TRUE/FALSE
  ##
  function version_lengths_differ()
  {
    local_var version_a = _FCT_ANON_ARGS[0];
    local_var version_b = _FCT_ANON_ARGS[1];
    local_var i;

    if (max_index(version_a) != max_index(version_b))
      return TRUE;

    for (i=0; i<max_index(version_a); i++)
    {
      if (max_index(version_a[i]) != max_index(version_b[i]))
        return TRUE;
    }

    return FALSE;
  }

  ##
  # Compare the two version segments
  #
  # @anonparam   1st segment (a)
  # @anonparam   2nd segment (b)
  #
  # @return -1 if a is lower than b; 0 if a is equal to b; 1 if a is higher than b
  ##
  function compare_version_segments()
  {
    local_var version_a = _FCT_ANON_ARGS[0];
    local_var version_b = _FCT_ANON_ARGS[1];

    if (is_alpha(version_a)) version_a = ord(version_a);
    if (is_alpha(version_b)) version_b = ord(version_b);

    if (version_a < version_b)
      return -1;
    else if (version_a > version_b)
      return 1;
    else return 0;
  }

  ###########
  # Parsing #
  ###########

  ##
  # Parses the given version
  # Output format: [[release segments], [pre-release segments]]
  #
  # @anonparam   1st   version to be parsed
  #
  # @return a nested list of version segs in the appropriate output format
  ##
  function parse_version()
  {
    local_var check_string = _FCT_ANON_ARGS[0];
    local_var release_segment, pre_release_seg;

    check_string = separate_version_segments(check_string);
    release_segment = check_string[0];
    pre_release_seg = check_string[1];

    # Parse release segment
    release_segment = parse_release_segment(release_segment);
    if (is_error(release_segment)) return release_segment;

    # Parse pre-release segment
    if (!empty(pre_release_seg))
    {
      pre_release_seg = parse_pre_release_segments(pre_release_seg);
      if (is_error(pre_release_seg)) return pre_release_seg;
    }
    else pre_release_seg = [0];

    return [release_segment, pre_release_seg];
  }

  ##
  # Split the version into two segments, a release segment and
  # a pre-release segment. This verbiage is taken from the semver spec
  #
  # @anonparam   1st   version to be split
  #
  # @return [release_segment, pre_release_segment]
  ##
  function separate_version_segments()
  {
    local_var check_string = _FCT_ANON_ARGS[0];
    local_var i, hyphen_index, conversion;

    foreach conversion (keys(conversions))
    {
      i = stridx(check_string, conversion);

      # conversion string not found
      if (i < 1) continue;

      # Many pre-release values are separated with a '-'
      # Account for this when necessary
      if (check_string[i-1] == '-') hyphen_index = i-1;
      else hyphen_index = i;

      # found something, split here
      return [substr(check_string, 0, hyphen_index-1), substr(check_string, i)];
    }

    # No pre-release segment
    return [check_string, ''];
  }

  ##
  # Parse the given release segment
  #
  # @anonparam   1st   string to parse
  #
  # @return a list of version segments in the overall release segment
  #         or an error
  ##
  function parse_release_segment()
  {
    local_var check_string = _FCT_ANON_ARGS[0];
    local_var segments = [];
    local_var i;

    for (i=0; i<strlen(check_string); i++)
    {
      # Whitespace not allowed in versions. If we see it, error.
      if (is_whitespace(check_string[i]))
        return parse_error(str:check_string, index:i, msg:'invalid whitespace in version string');

      if (is_digit(check_string[i]) || is_alpha(check_string[i]))
        segments[max_index(segments)] = get_next_segment(str:check_string, i:i); # i passed by ref and modified
      else if (is_separator(check_string[i]))
        continue;
      else return parse_error(str:check_string, index:i, msg:"invalid character in version string");
    }

    return segments;
  }

  ##
  # Obtain the next segment
  #
  # @param str   string we're iterating over
  # @param i     index to start at (passed by reference an modified within this function)
  #
  # @return value of next segment (string)
  ##
  function get_next_segment(str, &i)
  {
    local_var segment = '';

    if (is_digit(str[i]))
    {
      while ( i<strlen(str) && !is_separator(str[i]) && !is_alpha(str[i]) )
        segment += str[i++];
      i--; # We're 1 too far now, move back so we don't skip anything
      segment = int(segment);
    }
    else if (is_alpha(str[i]))
      segment = str[i];

    return segment;
  }

  ##
  # Parse the given pre-release segment
  #
  # @anonparam   1st   string to parse
  #
  # @return a list of version segments in the overall pre-release segment
  #         including converted values or an error
  ##
  function parse_pre_release_segments()
  {
    local_var check_string = _FCT_ANON_ARGS[0];
    local_var segments = [];
    local_var i, c;

    # We know this segment starts with a value that needs converting
    foreach c (keys(conversions))
    {
      if (c == substr(check_string, 0, strlen(c)-1))
      {
        segments[max_index(segments)] = conversions[c];
        break;
      }
    }

    for (i=strlen(c); i<strlen(check_string); i++)
    {
      # Whitespace not allowed in versions. If we see it, error.
      if (is_whitespace(check_string[i]))
        return parse_error(str:check_string, index:i, msg:'invalid whitespace in version string');

      if (is_digit(check_string[i]) || is_alpha(check_string[i]))
        segments[max_index(segments)] = get_next_segment(str:check_string, i:i); # i passed by ref and modified
      else if (is_separator(check_string[i]))
        continue;
      else return parse_error(str:check_string, index:i, msg:"invalid character in version string");
    }

    return segments;
  }

  ###########
  # Padding #
  ###########

  ##
  # Pad version lists so that they are the same length
  # Pads number segments that precede alpha if necessary
  # Segments are modified via pass-by-ref
  #
  # @param a   first version list
  # @param b   second version list
  #
  # @return NULL or Error
  ##
  function pad_segments(&a, &b)
  {
    local_var i, desired_length;

    # Start from the beginning of each segment and account for padding
    # that is needed between a number portion and letter portion
    for (i=0; (i<max_index(a) && i<max_index(b)); i++)
    {
      if ( (is_number(a[i]) && is_number(b[i])) || (is_alpha(a[i]) && is_alpha(b[i])) )
        continue;
      else if (is_alpha(a[i]))
        insert_element(idx:i, value:0, var:a);
      else if (is_alpha(b[i]))
        insert_element(idx:i, value:0, var:b);
    }

    a = pad_segments_list(segments:a, length:max_index(b));
    b = pad_segments_list(segments:b, length:max_index(a));

    if (max_index(a) != max_index(b))
      return new("vcf::Error", "An error occurred while attempting to pad the version segments.");
  }

  ##
  # Pad end of version segments list with 0s to meet given length
  #
  # @param segments   list of segments to pad
  # @param length     desired length of list
  #
  # @return list padded with 0s (if necessary)
  ##
  function pad_segments_list(segments, length)
  {
   local_var length_difference = length - max_index(segments);
   local_var i;

    if (length_difference <= 0) return segments;

    for (i = 0; i < length_difference; i++)
      segments[max_index(segments)] = 0;

    return segments;
  }

  ##################
  # Helper / Other #
  ##################

  function is_digit()  { return _FCT_ANON_ARGS[0] =~ '^[0-9]$'; }
  function is_number() { return _FCT_ANON_ARGS[0] =~ '^[0-9]+$'; }
  function is_alpha()  { return _FCT_ANON_ARGS[0] =~ '^[a-zA-Z]$'; }

  function is_whitespace()
  {
    switch (_FCT_ANON_ARGS[0])
    {
      case ' ', '\n', '\t', '\r':
        return TRUE;
      default:
        return FALSE;
    }
  }

  function is_separator()
  {
    local_var separator;
    foreach separator (separators)
      if (_FCT_ANON_ARGS[0] == separator)
        return TRUE;

    return FALSE;
  }

  ##
  # Prevents unwanted exits during unit testing
  #
  # @anonparam 1st status code
  # @anonparam 2nd message
  #
  # @return string or exits
  function vcf_exit()
  {
    local_var status_code = _FCT_ANON_ARGS[0];
    local_var message = _FCT_ANON_ARGS[1];

    if (TAP)
    {
      if (status_code == 0) return "Exit successful";
      else return "Fatal error";
    }

    exit(status_code, message);
  };
}
