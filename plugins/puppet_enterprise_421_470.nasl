#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95392);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/11/30 14:40:21 $");

  script_cve_id("CVE-2016-5715");
  script_bugtraq_id(93846);
  script_osvdb_id(145830, 145833);

  script_name(english:"Puppet Enterprise 2015.x / 2016.x < 2016.4.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the Puppet Enterprise version.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Puppet Enterprise
application running on the remote host is version 2015.x or 2016.x
prior to 2016.4.0. It is, therefore, affected by the following 
vulnerabilities :

  - A cross-site redirection vulnerability exists within the
    /auth/login script due to improper validation of
    user-supplied input to the 'redirect' parameter in a GET
    request. An unauthenticated, remote attacker can exploit
    this issue, by convincing a user to follow a specially
    crafted link, to redirect the user to a website of the
    attacker's own choosing, which can then be used to
    conduct further attacks. Note that this vulnerability
    was thought to have been resolved by the fix for
    CVE-2015-6501, but the fix was incomplete. Puppet
    Enterprise 2016.4.0 includes a fix for this
    vulnerability. (CVE-2015-5715)

  - A flaw exists in the Puppet Enterprise Console due to
    unsafe string processing that allows an authenticated,
    remote attacker to execute arbitrary code.
    (VulnDB 145833)");
  script_set_attribute(attribute:"see_also", value:"https://docs.puppet.com/release_notes/");
  script_set_attribute(attribute:"see_also", value:"https://puppet.com/security/cve/cve-2016-5715");
  script_set_attribute(attribute:"see_also", value:"https://puppet.com/security/cve/pe-console-oct-2016");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Puppet Enterprise version 2016.4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:puppetlabs:puppet");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies(
      "puppet_enterprise_console_detect.nasl",
      "puppet_rest_detect.nasl"
  );
  script_require_keys(
    "puppet/rest_port", 
    "installed_sw/puppet_enterprise_console"
  );

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Make sure we detected a version 
port = get_kb_item_or_exit('puppet/rest_port');
ver = get_kb_item_or_exit('puppet/' + port + '/version');

# Make sure the Console service is running
get_kb_item_or_exit('installed_sw/puppet_enterprise_console');

min_ver = '4.2.1'; # aka 2015.2.0; earliest 2015.x
fix_ver = '4.7.0'; # aka 2016.4.0

if(ver_compare(ver:ver, fix:fix_ver, minver: min_ver, strict:FALSE) < 0)
{
  report =
    '\n  Installed version : Puppet Enterprise ' + ver +
    '\n  Fixed version     : Puppet Enterprise 4.7.0 (2016.4.0)'
    + '\n';
  
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else
{
  audit(AUDIT_LISTEN_NOT_VULN, 'Puppet Enterprise', port, ver);
}

