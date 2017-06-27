#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84961);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/07/24 14:27:21 $");

  script_cve_id("CVE-2015-3900", "CVE-2015-4020", "CVE-2015-4100");
  script_bugtraq_id(75431, 75482);
  script_osvdb_id(122162, 123252, 123489);

  script_name(english:"Puppet Enterprise 3.7.x < 3.8.1 / 3.8.x < 3.8.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the Puppet Enterprise version.");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Puppet Enterprise
application running on the remote host is version 3.7.x or 3.8.x
prior to 3.8.1. It it, therefore, affected by the following
vulnerabilities :

  - A flaw exists in RubyGems due to a failure to validate
    hostnames when fetching gems or making API requests. A
    remote attacker, using a crafted DNS SRV record, can
    exploit this to redirect requests to arbitrary domains.
    (CVE-2015-3900)

  - A flaw exists in RubyGems due to a failure to sanitize
    DNS responses, which allows a man-in-the-middle attacker
    to install arbitrary applications. (CVE-2015-4020)

  - A flaw exists in Puppet Enterprise related to how
    certificates are managed, under certain vulnerable
    configurations, which allows a trusted certificate to be
    used to perform full certificate management. An attacker
    can exploit this flaw to revoke the certificates of
    other nodes or to approve their certificate requests.
    (CVE-2015-4100)

Note that the default 'monolithic', 'split', and 'multimaster'
installations of Puppet Enterprise are not affected by CVE-2015-4100.");
  script_set_attribute(attribute:"see_also", value:"https://puppetlabs.com/security/cve/CVE-2015-4100");
  script_set_attribute(attribute:"see_also", value:"http://blog.rubygems.org/2015/05/14/CVE-2015-3900.html");
  script_set_attribute(attribute:"see_also", value:"https://groups.google.com/forum/#!topic/puppet-announce/mnV70g2PttQ");
  script_set_attribute(attribute:"solution", value:"Upgrade to Puppet Enterprise 3.8.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:puppetlabs:puppet");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("puppet_rest_detect.nasl");
  script_require_keys("puppet/rest_port");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http_misc_func.inc");

app_name = "Puppet Enterprise";

port = get_kb_item_or_exit('puppet/rest_port');
ver = get_kb_item_or_exit('puppet/' + port + '/version');

if ('Enterprise' >< ver)
{
  # convert something like
  #   2.7.19 (Puppet Enterprise 2.7.0)
  # to
  #   2.7.0
  match = eregmatch(string:ver, pattern:"Enterprise ([0-9.]+)\)");
  if (isnull(match)) audit(AUDIT_UNKNOWN_WEB_APP_VER, app_name, build_url(port:port));
  ver = match[1];
}
else audit(AUDIT_WEB_APP_NOT_INST, app_name, port);

if (
  ver =~ "^3\.7($|[^0-9])" ||
  ver =~ "^3\.8\.0($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : Puppet Enterprise ' + ver +
      '\n  Fixed version     : Puppet Enterprise 3.8.1\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, build_url(port:port), ver);
