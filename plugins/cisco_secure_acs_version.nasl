#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69133);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/07/30 18:51:48 $");

  script_name(english:"Cisco Secure Access Control System Version");
  script_summary(english:"Gets the ACS version");

  script_set_attribute(
    attribute:"synopsis",
    value:"It is possible to obtain the version of the remote appliance."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running Cisco Secure Access Control System (ACS), an
access control management and appliance system. 

It is possible to get the ACS version number via SSH."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/ps9911/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:secure_acs");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/Cisco/show_ver");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

##
# Saves the Secure ACS version in the KB, generates plugin output, and exits
#
# @anonparam ver Secure ACS version number
# @anonparam source protocol used to obtain the version
# @remark this function never returns
##
function report_and_exit()
{
  local_var ver, display_ver, source, match, report;
  display_ver = _FCT_ANON_ARGS[0];
  source = _FCT_ANON_ARGS[1];

  # this assumes versions will only contain alphabetic characters all
  # the way at the end of the version when they are not consequential
  # (such as 5.4.0.46.0a which has the same patch level as 5.4.0.46.0
  # and 5.4.0.46). if this assumption is proven wrong, the following
  # regex needs to account for that. any plugin that uses this version
  # in a comparison might need to be changed as well so that they can
  # account for checking an alphanumeric version number
  match = eregmatch(string:display_ver, pattern:"^([\d.]+)");
  if (isnull(match))  # every ACS should at least begin with numbers so this is unlikely
    return;
  else
    ver = match[1];

  set_kb_item(name:"Host/Cisco/ACS/DisplayVersion", value:display_ver);
  set_kb_item(name:"Host/Cisco/ACS/Version", value:ver);

  if (report_verbosity > 0)
  {
    report =
      '\n  Source  : ' + source +
      '\n  Version : ' + display_ver +
      '\n';
    security_note(port:0, extra:report);
  }
  else security_note(0);

  exit(0);
}

# 1. SSH

is_secure_acs = get_kb_item("Host/Cisco/ACS");
showver = get_kb_item("Host/Cisco/show_ver");
if (is_secure_acs && !isnull(showver))
{
  match = eregmatch(string:showver, pattern:"Version : (.+)");
  if (!isnull(match))
  {
    report_and_exit(match[1], 'SSH');
    # never reached
  }
}

# The HTTP detection method will be disabled for now since it likely detects
# ACS on other platforms (like Windows) which seem to be treated like different
# products.  This could lead to false positives when doing version checks for
# missing patches that are only applicable to the appliance.
#
# if this is ever uncommented, "cisco_acs_detect.nbin" should be added as
# a dependency
#
# 2. HTTP
#
# This method should be used as a last resort because some versions of ACS report their
# version without including patch information (e.g. "5.4" instead of "5.4.0.46.4")
#port = get_http_port(default:443);
#ver = get_kb_item('www/' + port + '/CiscoSecure_ACS/Version');
#if (ver)
#{
#  report_and_exit(ver, 'HTTP');
#  # never reached
#}

if (is_secure_acs)
  exit(1, 'Unable to determine Secure ACS version number obtained via SSH.');
else
  exit(0, 'The Secure ACS version is not available (the remote host may not be Secure ACS).');
