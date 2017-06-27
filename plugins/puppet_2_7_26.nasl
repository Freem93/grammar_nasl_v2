#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76344);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/07/02 20:44:22 $");

  script_cve_id("CVE-2014-3248", "CVE-2014-3249", "CVE-2014-3250");
  script_bugtraq_id(68035, 68037);
  script_osvdb_id(108054, 108055, 108105);

  script_name(english:"Puppet < 2.7.26 / 3.6.2 and Enterprise 2.8.x < 2.8.7 Multiple Vulnerabilities");
  script_summary(english:"Checks puppet version.");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Puppet install on
the remote host is affected by multiple vulnerabilities :

  - A privilege escalation vulnerability related to input
    validation and paths exists in the bundled Ruby
    environment. An attacker could trick a privileged user
    into executing arbitrary code by convincing the user to
    change directories and then run Puppet.
    (CVE-2014-3248)

  - An error exists related to the console role that could
    allow unauthenticated users to obtain sensitive
    information by hiding and unhiding nodes. Note that
    this issue only affects Puppet Enterprise installs.
    (CVE-2014-3249)

  - An error exists related to configurations including
    Apache 2.4 and the mod_ssl 'SSLCARevocationCheck' that
    could allow an attacker to obtain sensitive
    information. Note that this issue does not affect
    Puppet Enterprise installs. (CVE-2014-3250)");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/cve-2014-3248");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/cve-2014-3249");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/cve-2014-3250");
  script_set_attribute(attribute:"solution", value:"Upgrade to Puppet 2.7.26 / 3.6.2 or Puppet Enterprise 2.8.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/02");

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
    (
      isnull(min_ver) &&
      ver_compare(ver:ver, fix:fix, strict:FALSE) < 0
    ) ||

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
        '\n  Fixed version     : Puppet Enterprise ' + fix + '\n';
    }
    else
    {
      report =
        '\n  Installed version : Puppet Open Source ' + ver +
        '\n  Fixed version     : Puppet Open Source ' + fix + '\n';
    }
  }
  else report = FALSE;

  return report;
}

port = get_kb_item_or_exit('puppet/rest_port');
ver = get_kb_item_or_exit('puppet/' + port + '/version');
report = FALSE;

if ('Enterprise' >< ver)
{
  app_name = "Puppet Enterprise";
  match = eregmatch(string:ver, pattern:"Enterprise ([0-9.]+)\)");
  if (isnull(match)) audit(AUDIT_UNKNOWN_WEB_APP_VER, app_name, build_url(port:port));
  ver = match[1];

  # Resolved in Puppet Enterprise 2.8.7
  report = _check_version(ver, '2.8.7', "2.8", enterprise:TRUE);
}
else
{
  # Do not run against open source unless scan is paranoid
  if (report_paranoia < 2) audit(AUDIT_PARANOID);

  app_name = "Puppet";

  # sanity check - make sure the version doesn't include letters or anything else unexpected
  match = eregmatch(string:ver, pattern:"^([0-9.]+)$");
  if (isnull(match)) audit(AUDIT_NONNUMERIC_VER, app_name, port, ver);
  ver = match[1];

  # Resolved in Puppet 2.7.26, 3.6.2
  report = _check_version(ver, '2.7.26', '0.0');
  if (!report)
    report = _check_version(ver, '3.6.2', '3.0');
}

if (!report) audit(AUDIT_LISTEN_NOT_VULN, app_name, port, ver);

if (report_verbosity > 0) security_warning(port:port, extra:report);
else security_warning(port);
