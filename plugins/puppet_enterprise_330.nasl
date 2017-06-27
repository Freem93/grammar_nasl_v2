#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77281);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id("CVE-2014-0198", "CVE-2014-0224", "CVE-2014-3251");
  script_bugtraq_id(67193, 67899, 69235);
  script_osvdb_id(106531, 109257);

  script_name(english:"Puppet Enterprise 2.8.x / 3.2.x Multiple Vulnerabilities");
  script_summary(english:"Checks the Puppet Enterprise version.");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Puppet Enterprise
application installed on the remote host is version 2.8.x or 3.2.x. It
is, therefore, affected by multiple vulnerabilities :

  - An error exists in the 'do_ssl3_write' function that
    permits a NULL pointer to be dereferenced, which could
    allow denial of service attacks. Note that this issue
    is exploitable only if SSL_MODE_RELEASE_BUFFERS is
    enabled. (CVE-2014-0198)

  - An error exists in the processing of ChangeCipherSpec
    messages that allows the usage of weak keying material.
    This permits simplified man-in-the-middle attacks to be
    done. (CVE-2014-0224)

  - The MCollective 'aes_security' plugin does not properly
    validate new server certificates. This allows a local
    attacker to spoof a valid MCollective connection. Note
    that this plugin is not enabled by default.
    (CVE-2014-3251)");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/CVE-2014-0198");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/CVE-2014-0224");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/CVE-2014-3251");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Puppet Enterprise 3.3.0 or later.

In the case of the 2.8.x branch, please contact the vendor for
guidance.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:puppetlabs:puppet");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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
        '\n  Fixed version     : Puppet Enterprise 3.3.0\n';
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

  if (ver =~ "^2\.8\.")
  {
    vuln = TRUE;
    report =
      '\n  Installed version : Puppet Enterprise ' + ver +
      '\n  Fixed version     : See solution.\n';
  }

  if (ver =~ "^3\.2\.")
  {
    report = _check_version(ver:ver, fix:'3.3.0', min_ver:'3.2.0', enterprise:TRUE);
    if (!isnull(report))
      vuln = TRUE;
  }
}

if (!vuln) audit(AUDIT_LISTEN_NOT_VULN, 'Puppet', port, ver);

if (report_verbosity > 0) security_warning(port:port, extra:report);
else security_warning(port);
