#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66236);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id("CVE-2013-1655");
  script_bugtraq_id(58442);
  script_osvdb_id(91224);

  script_name(english:"Puppet Unsafe YAML Unserialization");
  script_summary(english:"Checks puppet version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host has a code execution
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the Puppet install on
the remote host has a remote code execution vulnerability.  Specially
crafted YAML encoded objects are not unserialized safely.  A remote,
unauthenticated attacker could exploit this to execute arbitrary code. 

The issue is reportedly only exploitable when Puppet has the master role
enabled, and is configured to use Ruby 1.9.3 or later."
  );
  script_set_attribute(attribute:"see_also", value:"http://projects.puppetlabs.com/issues/19393");
  script_set_attribute(attribute:"see_also", value:"https://puppetlabs.com/security/cve/cve-2013-1655/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Puppet 2.7.21 / 3.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
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
function _check_version()
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
    report =
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix + '\n';
  }
  else report = NULL;

  return report;
}

port = get_kb_item_or_exit('puppet/rest_port');
ver = get_kb_item_or_exit('puppet/' + port + '/version');
roles = get_kb_item('puppet/' + port + '/roles');
rubyver = get_kb_item('puppet/' + port + '/rubyversion');
caveats = NULL;

# Do not run against open source unless scan is paranoid
if ('Enterprise' >!< ver && report_paranoia < 2) audit(AUDIT_PARANOID);

# convert something like
#   2.7.19 (Puppet Enterprise 2.7.0)
# to
#   2.7.19
match = eregmatch(string:ver, pattern:"([0-9.]+)( |$)");
if (isnull(match)) audit(AUDIT_FN_FAIL, 'eregmatch');
ver = match[1];

# the advisory says:
# This vulnerability only affects puppet masters running Ruby 1.9.3 and higher.
if (isnull(roles))
  caveats += '  Unable to determine if the host is configured as a puppet master\n';
else if('Master' >!< roles)
  audit(AUDIT_WRONG_WEB_SERVER, port, 'a puppet master');

if (isnull(rubyver))
  caveats += '  Unable to determine if Ruby version is >= 1.9.3\n';
else if (rubyver != '1.9.3' && ver_compare(ver:rubyver, fix:'1.9.3', strict:FALSE) < 0)
  audit(AUDIT_WRONG_WEB_SERVER, port, 'using Ruby 1.9.3 or later');

# from the bug tracker:
#   Merged into 3.1.0 in 4725c40e
#   Merged into 2.7.20 in 6aedf445c
#   Not merged into 2.6.17, because it only affects ruby 1.9.3 users
if (
  (report = _check_version(ver, '2.7.21', '2.7.0')) ||
  (report = _check_version(ver, '3.1.1', '3.0.0'))
)
{
  if (report_verbosity > 0)
  {
    if (!isnull(caveats))
    {
      report +=
        '\nPlease note Nessus was unable to determine if the following conditions' +
        '\nrequired to exploit the vulnerability are present :\n\n' +
        caveats;
    }
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'Puppet', port, ver);
