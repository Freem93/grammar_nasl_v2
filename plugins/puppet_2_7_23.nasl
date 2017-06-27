#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70661);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/01/28 00:52:45 $");

  script_cve_id("CVE-2013-4761", "CVE-2013-4956");
  script_bugtraq_id(61805, 61806);
  script_osvdb_id(96343, 96346);

  script_name(english:"Puppet 2.7.x / 3.2.x < 2.7.23 / 3.2.4 and Enterprise 2.8.x / 3.0.x < 2.8.3 / 3.0.1 Multiple Vulnerabilities");
  script_summary(english:"Checks puppet version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the Puppet install on
the remote host has multiple vulnerabilities:

  - By using the 'resource_type' service, an attacker could
    cause Puppet to load arbitrary Ruby files from the
    Puppet Master node's file system. While this behavior is
    not enabled by default, 'auth.conf' settings could be
    modified to allow it. The exploit requires local file
    system access to the Puppet Master. (CVE-2013-4761)

  - Puppet Module Tool (PMT) installs modules with weak
    permissions if those permissions were used when the
    modules were originally built. This could allow
    attackers to bypass certain security restrictions and
    perform unauthorized actions. (CVE-2013-4956)"
  );
  script_set_attribute(attribute:"see_also", value:"https://puppetlabs.com/security/cve/cve-2013-4761");
  script_set_attribute(attribute:"see_also", value:"https://puppetlabs.com/security/cve/cve-2013-4956");
  # https://github.com/puppetlabs/puppet/blob/master/acceptance/tests/security/cve-2013-4761_resource_type.rb
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c65953c7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Puppet 2.7.23 / 3.2.4 or Puppet Enterprise 2.8.3 / 3.0.1
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:puppetlabs:puppet");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

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
    (isnull(min_ver) &&
     ver_compare(ver:ver, fix:fix, strict:FALSE) < 0) ||

    # lower bound
    (!isnull(min_ver) &&
     ver_compare(ver:ver, fix:fix, strict:FALSE) < 0 &&
     ver_compare(ver:ver, fix:min_ver, strict:FALSE) >= 0)
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
  # convert something like
  #   2.7.19 (Puppet Enterprise 2.7.0)
  # to
  #   2.7.0
  match = eregmatch(string:ver, pattern:"Enterprise ([0-9.]+)\)");
  if (isnull(match)) audit(AUDIT_UNKNOWN_WEB_APP_VER, 'Puppet Enterprise', build_url(port:port));
  ver = match[1];

  # Resolved in Puppet Enterprise 2.8.3 or 3.0.1
  if (
      (report = _check_version(ver, '2.8.3', "2.8", enterprise:TRUE)) ||
      (report = _check_version(ver, '3.0.1', "3.0", enterprise:TRUE))
  ) vuln = TRUE;
}
else
{
  # Do not run against open source unless scan is paranoid
  if (report_paranoia < 2) audit(AUDIT_PARANOID);

  # sanity check - make sure the version doesn't include letters or anything else unexpected
  match = eregmatch(string:ver, pattern:"^([0-9.]+)$");
  if (isnull(match)) audit(AUDIT_NONNUMERIC_VER, 'Puppet', port, ver);
  ver = match[1];

  # Resolved in Puppet 2.7.23, 3.2.4
  if (
    (report = _check_version(ver, '2.7.23', '2.7')) ||
    (report = _check_version(ver, '3.2.4', '3.2'))
  ) vuln = TRUE;
}

if (!vuln) audit(AUDIT_LISTEN_NOT_VULN, 'Puppet', port, ver);

if (report_verbosity > 0) security_warning(port:port, extra:report);
else security_warning(port);
