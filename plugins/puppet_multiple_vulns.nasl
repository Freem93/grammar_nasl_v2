#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66237);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/16 14:22:07 $");

  script_cve_id(
    "CVE-2013-1640",
    "CVE-2013-1652",
    "CVE-2013-1654",
    "CVE-2013-2275"
  );
  script_bugtraq_id(58443, 58449, 58452, 58453);
  script_osvdb_id(56387, 91222, 91223, 91226, 91227);

  script_name(english:"Puppet Multiple Vulnerabilities (2013/03/12)");
  script_summary(english:"Checks puppet version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A configuration management application running on the remote host has
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the version of Puppet
Open Source or Puppet Enterprise running on the remote host has the
following vulnerabilities :

  - A vulnerability that allows an authenticated client to
    execute arbitrary code on a puppet master.
    (CVE-2013-1640)

  - A vulnerability that allows an authenticated client to
    connect to a puppet master and perform unauthorized
    actions. (CVE-2013-1652)

  - A vulnerability that would allow a man-in-the-middle
    attacker to downgrade an HTTPS connection to use SSLv2.
    (CVE-2013-1654)

  - A vulnerability that allows an authenticated node to
    submit a report for any other node.  This issue only
    affects puppet masters 0.25.0 and above. (CVE-2013-2275)"
  );
  script_set_attribute(attribute:"see_also", value:"https://puppetlabs.com/security/cve/CVE-2013-1640/");
  script_set_attribute(attribute:"see_also", value:"https://puppetlabs.com/security/cve/CVE-2013-1652/");
  script_set_attribute(attribute:"see_also", value:"https://puppetlabs.com/security/cve/CVE-2013-1654/");
  script_set_attribute(attribute:"see_also", value:"https://puppetlabs.com/security/cve/CVE-2013-2275/");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade Puppet Open Source to 2.6.18 / 2.7.21 / 3.1.1 or later.
Upgrade Puppet Enterprise to 1.2.7 / 2.7.2 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:puppetlabs:puppet");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("puppet_rest_detect.nasl");
  script_require_keys("puppet/rest_port");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

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
  if (isnull(match)) audit(AUDIT_FN_FAIL, 'eregmatch');
  ver = match[1];

  # Resolved in Puppet Enterprise 1.2.7, 2.7.2
  if (
    (report = _check_version(ver, '1.2.7', enterprise:TRUE)) ||
    (report = _check_version(ver, '2.7.2', '2.7', enterprise:TRUE))
  ) vuln = TRUE;
}
else
{
  # Do not run against open source unless scan is paranoid
  if (report_paranoia < 2) audit(AUDIT_PARANOID);

  # sanity check - make sure the version doesn't include letters or anything else unexpected
  match = eregmatch(string:ver, pattern:"^([0-9.]+)$");
  if (isnull(match)) audit(AUDIT_FN_FAIL, 'eregmatch');
  ver = match[1];

  # Resolved in Puppet 2.6.18, 2.7.21, 3.1.1
  if (
    (report = _check_version(ver, '2.6.18')) ||
    (report = _check_version(ver, '2.7.21', '2.7')) ||
    (report = _check_version(ver, '3.1.1', '3.0'))
  ) vuln = TRUE;
}

if (!vuln) audit(AUDIT_LISTEN_NOT_VULN, 'Puppet', port, ver);

if (report_verbosity > 0) security_hole(port:port, extra:report);
else security_hole(port);
