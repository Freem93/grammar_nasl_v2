#TRUSTED 188cbe2c16bbdb2a472cc77ecc2707d9f432155230fe7518b74de8fb7650490c821b0d55ed08c8afa81db1a92b865b8bcf6a201aa260c951880ea7e4e2b67b6ecf2056a0ea8fce17f8bfe5a957a696022f311d72b324ef665bbdae6b30e6193ddf6825c08761bc4d0154a2cc0f8cefed453b4630a0bfaa0b957577c6e586beddeaf16fea38195cc11b10a7a08ee4ae7939a55bff2e8c860a3559245e4331df172f12e962280d533b4d83c2ff0809ef68397c3c979237f68a53cfcbd26ae8fc0a463663bf20d47b4ffd4887582a584f4734b2be354f6acfc2ca0b2e6dec43d61163dd5db906f04600c950f8ea4f9c4b610e820fbd33ffd670b241cb649e2109d8b6d218707cf744b370ac0cee5d7a77065aca0e008d847078d9ca9d7c6c44ff4d3099b539f249c834adc0b7d5b9aec6a643097034e21c2e98ba8e98c29b51c62dc248bad12bfc65b7f415eeaed15cfdc16f5304bf2abf68a271301eecd796e175548396e4f17008e076e7c30c3b35a1d87aefa8ce8a312f1df8300ad59f529408cebbdcc580f3c265885690db1e263d967afcb1024b063750bc1c7af54925c25a31fe88b8ddc3a86d9073a8f38b93a7b6070a175fb5e3d0f5b031197a69ae0b78058f6cf58a7beee5e84d99f858f2e518ca27b918a4f65e08c7e21c7e356d16b5df2762d4359f268788516415850a9a008c428ae2c6a9d1086ba68c7b3e287779
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# vcf_extras.inc
#
# Revision: 1.3

namespace vcf
{
  ######################
  # Special Snowflakes #
  ######################
  # Items implemented within this file are due to products/vendors/plugin groups
  # that require special implementations of certain features. These are typically
  # re-implementations of the get_app_info() when detections for certain plugins
  # groups do not store the necessary information in one of the usual ways.
  # The primary purpose of this include is to keep things out of the core vcf
  # library and avoid extra bloat and tacked on functionality that is only used
  # in certain, specific scenarios.

  namespace adobe_reader
  {
    ##
    # Get info for Adobe Reader
    # @return an app_info array for Adobe Reader
    ##
    function get_app_info()
    {
      local_var app_info = {};
      local_var install = get_single_install(app_name:"Adobe Reader");
      local_var win_port;

      app_info.app = "Adobe Reader";

      app_info.version = install.DLL_Product_Version;
      app_info.path = install.path;
      app_info.display_version = install.DLL_Display_Version;
      app_info.parsed_version = parse_version(app_info.version);

      win_port = get_kb_item("SMB/transport");
      if (!win_port) app_info.port = 445;
      else app_info.port = win_port;

      return app_info;
    }
  }

  namespace apple
  {
    ##
    # Get info for Apple Safari
    # @return an app_info array for Apple Safari
    ##
    function get_safari_info()
    {
      local_var app_info = {"app" : "Safari"};

      get_kb_item_or_exit("MacOSX/Safari/Installed", exit_code:0);
      app_info.path = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
      app_info.version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);
      app_info.parsed_version = parse_version(app_info.version);

      return app_info;
    }

    ##
    # Get info for macOS or OS X
    # @return an app_info array for macOS
    ##
    function get_macos_info()
    {
      local_var os, c, matches, version;
      os = get_kb_item("Host/MacOSX/Version");
      if (!os)
      {
        os = get_kb_item_or_exit("Host/OS");
        if ("Mac OS X" >!< os) ::audit(AUDIT_OS_NOT, "macOS / Mac OS X");

        c = get_kb_item("Host/OS/Confidence");
        if (c <= 70) exit(1, "Can't determine the host's OS with sufficient confidence.");
      }
      if (!os) ::audit(AUDIT_OS_NOT, "macOS / Mac OS X");

      matches = eregmatch(pattern:"Mac OS X ([0-9]+(\.[0-9]+)+)", string:os);
      if (isnull(matches)) exit(1, "Failed to parse the macOS / Mac OS X version ('" + os + "').");

      version = matches[1];

      return { "version":version, "parsed_version":parse_version(version) };
    }

    ##
    # Check if the macOS version of the host meets the required version
    # 
    # @param restrictions  a list of macOS version that the host is required to be
    # @return NULL or audits
    # @remark This assumes OS version values have 2 or 3 segments. Another other amount
    #         of segments will raise an error.
    ##
    function check_macos_restrictions(restrictions)
    {
      local_var restriction, tmp, upper_bound;
      local_var os = get_macos_info();
      local_var constraints = {};
      local_var i = 0;

      foreach restriction (restrictions)
      {
        # Build fixed_version (used to set upper bounds for the constraint)
        tmp = parse_version(restriction);
        upper_bound = string(tmp[0][0]) + "." + string(int(tmp[0][1]) + 1);

        # Add constraint
        constraints[i++] = { min_version : restriction, fixed_version : upper_bound};
      }

      if (!check_version(version:os.parsed_version, constraints:constraints))
        return vcf_exit(0, "The remote host's OS (macOS " + os.version + ") is not an affected macOS / Mac OS X version (" + join(restrictions, sep:", ") + ").");
    }
  }

  namespace bind
  {
    ##
    # Adds appropriate conversion values and additional separator
    # @return NULL
    ##
    function initialize()
    {
      add_conversions({'a':conversions.alpha, 'b':conversions.beta});
      add_separator('-');
    }

    ##
    # Filters out constraints based on version.
    # Basically, "-S" versions should only be checked
    # against each other since these versions, while
    # applicable to other releases, are paid releases
    # that not all customers have access to
    #
    # @param  constraints  list of constraints to validate
    # @param  version      the version of bind to validate with
    #
    # @return array of constraints
    ##
    function filter_constraints(constraints, version)
    {
      # No need to worry
      if ("-S" >< version) return constraints;
      else # Remove subscriber-only constraints
      {
        local_var i, value;
        for (i=0; i<max_index(constraints); i++)
          if ("-S" >< constraints[i].fixed_version)
            delete_element(idx:i, var:constraints);
      }
      return constraints;
    }
  }

  namespace ibm
  {
    ##
    # Verify that the required websphere mq components are installed
    # and that the install is of the desired flavor
    #
    # @param  app_info            an app_info structure for websphere mq
    # @param  required_flavor     the required application flavor
    # @param  required_component  a required component
    #
    # @return NULL or audit
    ##
    function verify_websphere_mq_component(app_info, required_flavor, required_component)
    {
      local_var installed_components, installed_component, required_component_is_present;

      if (isnull(app_info)) return arg_error(arg:"app_info", func:FUNCTION_NAME);

      if (!isnull(required_flavor))
        if (tolower(required_flavor) != tolower(app_info['Type']))
          ::audit(AUDIT_NOT_INST, "IBM WebSphere MQ type '" + required_flavor + "'");

      # Check or ignore components (explorer, javamsg, server, ...)
      if (!isnull(required_component))
      {
        installed_components = split(app_info['Components'], sep:",", keep:FALSE);

        foreach installed_component (installed_components)
        {
          installed_component = ereg_replace(
            string:installed_component,
            pattern:" ",
            replace:""
          );

          if (tolower(installed_component) == tolower(required_component))
            return;
        }

        ::audit(AUDIT_NOT_INST, "IBM WebSphere MQ component '" + required_component + "'");
      }
    }
  }
}
