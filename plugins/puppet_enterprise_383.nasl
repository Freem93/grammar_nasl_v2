#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87472);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/29 19:06:13 $");

  script_cve_id("CVE-2015-7328");
  script_osvdb_id(129970);

  script_name(english:"Puppet Enterprise Installation Process Local CA Key Disclosure");
  script_summary(english:"Checks the Puppet Enterprise version.");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host is affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Puppet Enterprise
application installed on the remote host is version 3.8.x prior to
3.8.3 or 4.2.x prior to 4.2.3. It is, therefore, affected by an
information disclosure vulnerability due to the generated CA key being
left in a world-readable state during initial installation and
configuration. A local attacker can exploit this to gain access to
CA key information.");
  script_set_attribute(attribute:"see_also", value:"http://docs.puppetlabs.com/release_notes/");
  script_set_attribute(attribute:"see_also", value:"https://puppetlabs.com/security/cve/cve-2015-7328");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Puppet Enterprise version 3.8.3 / 4.2.3 or later. Note that
version 4.2.3 is also known as Puppet Enterprise 2015.2.3");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:puppetlabs:puppet");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies(
      "puppet_enterprise_console_detect.nasl",
      "puppet_rest_detect.nasl"
  );
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
# @anonparam min_ver the earliest vulnerable version (optional)
#
# @return plugin output if 'ver' is vulnerable relative to 'fix' and/or 'min_ver',
#         NULL otherwise
##
function _check_version(ver, fix, min_ver, enterprise)
{
  local_var report = NULL;

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
        '\n  Fixed version     : Puppet Enterprise 3.8.3 or 2015.2.3'
        + '\n';
    }
  }

  return report;
}

port = get_kb_item_or_exit('puppet/rest_port');
ver = get_kb_item_or_exit('puppet/' + port + '/version');
report = NULL;
vuln = FALSE;
product = ""; # Enterprise or Open Source

# Enterprise versions <= 3.8.3 have a unique HTTP header text
# E.g. X-Puppet-Version: 3.8.4 (Puppet Enterprise 3.8.3)
if ('Enterprise' >< ver)
{
  product = "Puppet Enterprise";
  # convert something like
  #   2.7.19 (Puppet Enterprise 2.7.0)
  # to
  #   2.7.0
  match = eregmatch(string:ver, pattern:"Enterprise ([0-9.]+)\)");
  if (isnull(match))
    audit(AUDIT_UNKNOWN_WEB_APP_VER, product, build_url(port:port));
  ver = match[1];

  if (ver =~ "^3\.8\.")
  {
    report = _check_version(
        ver:ver,
        fix:'3.8.3',
        min_ver:'3.8.0',
        enterprise:TRUE
    );
    if (!isnull(report)) vuln = TRUE;
  }
}
# The newer enterprise versions do not have the 'Enterprise'
# text in the HTTP header, so we need to check if the Puppet
# Enterprise Console was detected. Puppet Open Source does not come
# with a web console user interface out of the box.
else if (get_kb_item('installed_sw/puppet_enterprise_console'))
{
  product = "Puppet Enterprise";
  if (ver =~ "^4\.2\.")
  {
    report = _check_version(
        ver:ver,
        fix:'4.2.3',
        min_ver:'4.2.0',
        enterprise:TRUE
    );
    if (!isnull(report)) vuln = TRUE;
  }
}
# otherwise, it's the open source edition
else
{
  product = "Puppet Open Source";
  vuln = FALSE;
}

if (!vuln) audit(AUDIT_LISTEN_NOT_VULN, product, port, ver);

if (report_verbosity > 0) security_note(port:port, extra:report);
else security_note(port);
