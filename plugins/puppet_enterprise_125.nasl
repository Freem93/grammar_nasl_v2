#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73824);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/23 22:03:56 $");

  script_cve_id("CVE-2012-0891");
  script_bugtraq_id(66602);
  script_osvdb_id(84561);

  script_name(english:"Puppet Enterprise Multiple XSS Vulnerabilities");
  script_summary(english:"Checks puppet enterprise version");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host is potentially affected by
multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Puppet Enterprise
install on the remote host is later than version 1.0 but prior to
1.2.5 / 2.0.1. It is, therefore, affected by multiple cross-site
scripting vulnerabilities.

Multiple cross-site scripting flaws exist where unspecified input is
not validated before being returned to the user. This could allow a
remote attacker to execute arbitrary code within the browser and
server trust relationship.

Note that Nessus has not tested for these issues or otherwise
determine if the patch has been applied. But, has instead relied only
on the application's self-reported version number.

Note that Nessus has not tested for these issues or otherwise
determined if a hotfix is applied but has instead relied only on the
application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/cve-2012-0891");
  script_set_attribute(attribute:"solution", value:"Upgrade to Puppet Enterprise 1.2.5 / 2.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:puppetlabs:puppet");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("puppet_rest_detect.nasl");
  script_require_keys("puppet/rest_port", "Settings/ParanoidReport");

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
        '\n  Fixed version     : Puppet Enterprise ' + fix + '\n';
    }
    else
    {
      report =
        '\n  Installed version : Puppet Open Source ' + ver +
        '\n  Fixed version     : Puppet Open Source ' + fix + '\n';
    }
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
  # nb: hotfixes are not reflected in the version number.
  if (report_paranoia < 2) audit(AUDIT_PARANOID);

  # convert something like
  #   2.7.19 (Puppet Enterprise 2.7.0)
  # to
  #   2.7.0
  match = eregmatch(string:ver, pattern:"Enterprise ([0-9.]+)\)");
  if (isnull(match)) audit(AUDIT_UNKNOWN_WEB_APP_VER, 'Puppet Enterprise', build_url(port:port));
  ver = match[1];

  # Resolved in Puppet Enterprise 1.2.5 and 2.0.1
  if (
    (report = _check_version(ver, '1.2.5', '1.0', enterprise:TRUE)) ||
    (report = _check_version(ver, '2.0.1', '2.0', enterprise:TRUE))
  ) vuln = TRUE;
}


if (!vuln) audit(AUDIT_LISTEN_NOT_VULN, 'Puppet', port, ver);

set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

if (report_verbosity > 0) security_warning(port:port, extra:report);
else security_warning(port);
