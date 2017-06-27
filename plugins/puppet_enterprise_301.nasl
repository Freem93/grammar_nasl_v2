#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70663);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id(
    "CVE-2013-4073",
    "CVE-2013-4761",
    "CVE-2013-4762",
    "CVE-2013-4955",
    "CVE-2013-4956",
    "CVE-2013-4958",
    "CVE-2013-4959",
    "CVE-2013-4961",
    "CVE-2013-4962",
    "CVE-2013-4963",
    "CVE-2013-4964",
    "CVE-2013-4967",
    "CVE-2013-4968"
  );
  script_bugtraq_id(
    60843,
    61805,
    61806,
    61856,
    61857,
    61859,
    61860,
    61861,
    61862,
    61870,
    61945,
    61949,
    66541
  );
  script_osvdb_id(
    94628,
    96336,
    96337,
    96338,
    96339,
    96340,
    96341,
    96342,
    96343,
    96344,
    96345,
    96346,
    96347,
    96354
  );

  script_name(english:"Puppet Enterprise < 3.0.1 Multiple Vulnerabilities");
  script_summary(english:"Checks puppet enterprise version");

  script_set_attribute(
    attribute:"synopsis",
    value:"A web application on the remote host has multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the Puppet Enterprise
install on the remote host is a version prior to 3.0.1.  As a result,
it reportedly has multiple vulnerabilities:

  - An error exists related to the included Ruby SSL client
    that could allow man-in-the-middle attacks.
    (CVE-2013-4073)

  - An error exists related to the 'resource_type' service
    that could allow a local attacker to cause arbitrary
    Ruby files to be executed. (CVE-2013-4761)

  - Multiple session vulnerabilities exist that could
    allow an attacker to hijack an arbitrary session and
    gain unauthorized access. (CVE-2013-4762, CVE-2013-4964)

  - An error exists related to 'Puppet Module Tool' (PMT)
    and improper permissions. (CVE-2013-4956)

  - Multiple security bypass vulnerabilities exist that
    could allow an attacker to gain unauthorized access
    and perform sensitive transactions. (CVE-2013-4958,
    CVE-2013-4962)

  - Multiple information disclosure vulnerabilities exist
    that could allow an attacker to access sensitive
    information such as server software versions, MAC
    addresses, SSH keys, and database passwords.
    (CVE-2013-4959, CVE-2013-4961, CVE-2013-4967)

  - An open-redirection vulnerability exists that could
    allow an attacker to attempt a phishing attack.
    (CVE-2013-4955)

  - Clickjacking and cross-site-scripting vulnerabilities
    exist that could allow an attacker to trick users into
    sending them sensitive information such as passwords.
    (CVE-2013-4968)

  - A cross-site request forgery vulnerability exists that
    could allow an attacker to manipulate a logged in user's
    browser to perform sensitive transactions on the user's
    behalf. (CVE-2013-4963)"
  );
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/cve-2013-4073");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/cve-2013-4761");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/cve-2013-4762");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/cve-2013-4955");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/cve-2013-4956");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/cve-2013-4958");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/cve-2013-4959");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/cve-2013-4961");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/cve-2013-4962");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/cve-2013-4963");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/cve-2013-4964");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/cve-2013-4967");
  script_set_attribute(attribute:"see_also", value:"http://puppetlabs.com/security/cve/cve-2013-4968");
  script_set_attribute(attribute:"solution", value:"Upgrade to Puppet Enterprise 3.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/28");

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
        '\n  Fixed version : Puppet Enterprise ' + fix + '\n';
    }
    else
      report = NULL;
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
  if (isnull(match))
    audit(AUDIT_UNKNOWN_WEB_APP_VER, 'Puppet Enterprise', build_url(port:port));
  else
    ver = match[1];

  # Resolved in Puppet Enterprise 3.0.1
  if (report = _check_version(ver, '3.0.1', enterprise:TRUE))
  {
    vuln = TRUE;
  }
}

if (!vuln) audit(AUDIT_LISTEN_NOT_VULN, 'Puppet', port, ver);

set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
set_kb_item(name:"www/"+port+"/XSRF", value:TRUE);

if (report_verbosity > 0) security_warning(port:port, extra:report);
else security_warning(port);
