#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73132);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/11 21:07:51 $");

  script_cve_id(
    "CVE-2013-4164",
    "CVE-2013-4363",
    "CVE-2013-4491",
    "CVE-2013-4969",
    "CVE-2013-6414",
    "CVE-2013-6415",
    "CVE-2013-6417"
  );
  script_bugtraq_id(62442, 63873, 64074, 64076, 64077, 64106, 64552);
  script_osvdb_id(
    97163,
    100113,
    100524,
    100525,
    100527,
    100528,
    101432
  );

  script_name(english:"Puppet Enterprise 3.x < 3.1.1 Multiple Vulnerabilities");
  script_summary(english:"Checks Puppet Enterprise version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the Puppet Enterprise
3.x install on the remote host is prior to 3.1.1.  As a result, it is
reportedly affected by multiple vulnerabilities :

  - An input validation error exists related to the
    included Ruby version, handling string to floating point
    conversions that could allow denial of service attacks
    or arbitrary code execution. (CVE-2013-4164)

  - An error exists related to the included RubyGems
    version and 'gem build', 'Gem::Package', and
    'Gem::PackageTask' API calls that could allow denial
    of service attacks. (CVE-2013-4363)

  - An error exists in the 'i18n' gem for Ruby that could
    allow cross-site scripting attacks. (CVE-2013-4491)

  - An error exists related to handling temporary files
    that could allow a local attacker to overwrite files by
    using a symlink attack. (CVE-2013-4969)

  - An error exists related to the included Ruby on Rails,
    'Action View', and handling certain headers that could
    allow denial of service attacks. (CVE-2013-6414)

  - An input validation error exists related to the
    included Ruby on Rails and the 'unit' parameter in the
    'number_to_currency' helper that could allow cross-site
    scripting attacks. (CVE-2013-6415)

  - An input validation error exists related to the
    included Ruby on Rails, JSON parameter parsing and SQL
    queries that could allow SQL injection attacks.
    (CVE-2013-6417)"
  );
  script_set_attribute(attribute:"see_also", value:"https://groups.google.com/forum/#!topic/puppet-users/f_gybceSV6E");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/CVE-2013-4164");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/CVE-2013-4363");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/CVE-2013-4491");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/CVE-2013-4969");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/CVE-2013-6414");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/CVE-2013-6415");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/CVE-2013-6417");
  script_set_attribute(attribute:"solution", value:"Upgrade to Puppet Enterprise 3.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
  
script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:puppetlabs:puppet");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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

  # Resolved in Puppet Enterprise 3.1.1
  if (report = _check_version(ver, '3.1.1', '3.0.0', enterprise:TRUE))
  {
    vuln = TRUE;
  }
}

if (!vuln) audit(AUDIT_LISTEN_NOT_VULN, 'Puppet', port, ver);

set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

if (report_verbosity > 0) security_warning(port:port, extra:report);
else security_warning(port);
