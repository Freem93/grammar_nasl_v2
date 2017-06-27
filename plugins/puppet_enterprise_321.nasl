#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73135);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/18 15:00:16 $");

  script_cve_id("CVE-2013-4966", "CVE-2013-4971", "CVE-2014-0060", "CVE-2014-0082");
  script_bugtraq_id(65604, 65723, 65992, 65993);
  script_osvdb_id(103440, 103544, 104041, 104042);

  script_name(english:"Puppet Enterprise 3.x < 3.2.0 Multiple Vulnerabilities");
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
3.x install on the remote host is prior to 3.2.0.  As a result, it is
reportedly affected by multiple vulnerabilities :

  - An error exists related to the PE consoles and
    identity verification that could allow security
    bypasses. (CVE-2013-4966)

  - An unspecified error exists related to endpoint nodes
    that could allow information disclosure. (CVE-2013-4971)

  - SET ROLE bypasses lack of ADMIN OPTION when granting
    roles. (CVE-2014-0060)

  - An error exists in the included Ruby on Rails version
    related to the text rendering component of Action View
    and handling MIME types that are converted to symbols
    that could allow denial of service attacks.
    (CVE-2014-0082)"
  );
  # https://groups.google.com/forum/#!searchin/puppet-users/3.2.1/puppet-users/7eK2Qs3XALU/G2nGJg4iTS4J
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?864eaaed");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/CVE-2013-4966");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/CVE-2013-4971");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/CVE-2014-0060");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/CVE-2014-0082");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Puppet Enterprise 3.2.1 or later.

Note that the issues were reportedly addressed in 3.2.0, but that
release was pulled because it contained two major issues.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/04");
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
        '\n  Fixed version     : Puppet Enterprise 3.2.1\n'; # 3.2.0 was pulled
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

  # Resolved in Puppet Enterprise 3.2.0 (but this version was pulled)
  if (report = _check_version(ver, '3.2.0', '3.0.0', enterprise:TRUE))
  {
    vuln = TRUE;
  }
}

if (!vuln) audit(AUDIT_LISTEN_NOT_VULN, 'Puppet', port, ver);

if (report_verbosity > 0) security_warning(port:port, extra:report);
else security_warning(port);
