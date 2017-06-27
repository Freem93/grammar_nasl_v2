#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77282);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/28 19:00:57 $");

  script_cve_id(
    "CVE-2014-2483",
    "CVE-2014-2490",
    "CVE-2014-4208",
    "CVE-2014-4209",
    "CVE-2014-4216",
    "CVE-2014-4218",
    "CVE-2014-4219",
    "CVE-2014-4220",
    "CVE-2014-4221",
    "CVE-2014-4223",
    "CVE-2014-4227",
    "CVE-2014-4244",
    "CVE-2014-4247",
    "CVE-2014-4252",
    "CVE-2014-4262",
    "CVE-2014-4263",
    "CVE-2014-4264",
    "CVE-2014-4265",
    "CVE-2014-4266",
    "CVE-2014-4268"
  );
  script_bugtraq_id(
  68562,
  68571,
  68576,
  68580,
  68583,
  68590,
  68596,
  68599,
  68603,
  68608,
  68612,
  68615,
  68620,
  68624,
  68626,
  68632,
  68636,
  68639,
  68642,
  68645
  );
  script_osvdb_id(
  109124,
  109125,
  109126,
  109127,
  109128,
  109129,
  109130,
  109131,
  109132,
  109133,
  109134,
  109135,
  109136,
  109137,
  109138,
  109139,
  109140,
  109141,
  109142,
  109143
  );

  script_name(english:"Puppet Enterprise 3.3.0 Bundled Oracle Java Vulnerabilities");
  script_summary(english:"Checks the Puppet Enterprise version.");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Puppet Enterprise
application installed on the remote host is version 3.3.0. Therefore,
it contains a bundled version of Oracle Java that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/oracle-july-2014-vulnerability-fix");
  # http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4743a1ef");
  script_set_attribute(attribute:"solution", value:"Upgrade to Puppet Enterprise 3.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/20");

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
function _check_version(ver, fix, min_ver, enterprise)
{
  local_var report;

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
        '\n  Fixed version     : Puppet Enterprise 3.3.1\n';
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

  if (ver =~ "^3\.3\.")
  {
    report = _check_version(ver:ver, fix:'3.3.1', min_ver:'3.3.0', enterprise:TRUE);
    if (!isnull(report))
      vuln = TRUE;
  }
}

if (!vuln) audit(AUDIT_LISTEN_NOT_VULN, 'Puppet', port, ver);

if (report_verbosity > 0) security_hole(port:port, extra:report);
else security_hole(port);
