#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73377);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/04/07 16:38:19 $");

  script_cve_id("CVE-2012-5158");
  script_bugtraq_id(66641);
  script_osvdb_id(91262);

  script_name(english:"Puppet Enterprise 2.x < 2.6.1 Session Handling Weakness");
  script_summary(english:"Checks Puppet Enterprise version");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host is affected by a session handling
weakness.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Puppet Enterprise
2.x install on the remote host is prior to 2.6.1. As a result, it is
reportedly affected by a session handling weakness. An error exists
related to session handling, session secret regeneration, and a lack
of proper termination of current sessions. An authenticated user may
still be able to access the application after the session secret is
changed.");
  # https://groups.google.com/forum/?fromgroups=#!topic/puppet-announce/nH1sCnYspXc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?239ca43b");
  script_set_attribute(attribute:"see_also", value:"https://puppetlabs.com/security/cve/cve-2012-5158");
  script_set_attribute(attribute:"solution", value:"Upgrade to Puppet Enterprise 2.6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:puppetlabs:puppet");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("puppet_rest_detect.nasl");
  script_require_keys("puppet/rest_port");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http_misc_func.inc");
include("webapp_func.inc");

##
# checks if the given version falls between the given bounds, and
# generates plugin output if it does
#
# @anonparam ver version to check
# @anonparam fix first fixed version
# @anonparam min_ver the lowest/earliest vulnerable version, relative to 'fix' (optional)
#
# @return plugin output if 'ver' is vulnerable relative to 'fix' and/or 'min_ver',
#         NULL otherwise
##
function _check_version(enterprise)
{
  local_var ver, fix, min_ver, major_ver, report;
  ver = _FCT_ANON_ARGS[0];
  fix = _FCT_ANON_ARGS[1];
  min_ver = _FCT_ANON_ARGS[2];

  if (
    # no lower bound
    (isnull(min_ver) && ver_compare(ver:ver, fix:fix, strict:FALSE) < 0) ||

    # lower bound
    (
      !isnull(min_ver) &&
      ver_compare(ver:ver, fix:fix, strict:FALSE) < 0 &&
      ver_compare(ver:ver, fix:min_ver, strict:FALSE) >= 0
    )
  )
  {
    if (enterprise)
    {
      report =
        '\n  Installed version : Puppet Enterprise ' + ver +
        '\n  Fixed version     : Puppet Enterprise ' + fix + 
        '\n';
    }
    else report = NULL;
  }
  else report = NULL;

  return report;
}

port = get_kb_item_or_exit('puppet/rest_port');
ver = get_kb_item_or_exit('puppet/' + port + '/version');
report = NULL;
vuln = FALSE;

if ('Enterprise' >< ver)
{
  # convert something like
  #   2.7.19 (Puppet Enterprise 2.7.0)
  # to
  #   2.7.0
  match = eregmatch(string:ver, pattern:"Enterprise ([0-9.]+)\)");
  if (isnull(match)) audit(AUDIT_UNKNOWN_WEB_APP_VER, 'Puppet Enterprise', build_url(port:port));
  ver = match[1];

  if (report = _check_version(ver, '2.6.1', '2.0.0', enterprise:TRUE))
    vuln = TRUE;
}

if (!vuln) audit(AUDIT_LISTEN_NOT_VULN, 'Puppet', port, ver);

if (report_verbosity > 0) security_warning(port:port, extra:report);
else security_warning(port);
