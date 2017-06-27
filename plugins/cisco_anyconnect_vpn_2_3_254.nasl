#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54954);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2011-2039", "CVE-2011-2041");
  script_bugtraq_id(48077, 48081);
  script_osvdb_id(72714, 72716);
  script_xref(name:"CISCO-BUG-ID", value:"CSCsy00904");
  script_xref(name:"CISCO-BUG-ID", value:"CSCta40556");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20110601-ac");
  script_xref(name:"CERT", value:"490097");
  script_xref(name:"EDB-ID", value:"17366");

  script_name(english:"Cisco AnyConnect Secure Mobility Client < 2.3.254 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The VPN client installed on the remote Windows host has multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Cisco AnyConnect Secure Mobility Client installed on
the remote host is earlier than 2.3.254 and may have the following
vulnerabilities :

  - When the client is obtained from the VPN headend using
    a web browser, a helper application performs the
    download and installation.  This helper application does
    not verify the authenticity of the downloaded installer,
    which could allow an attacker to send malicious code to
    the user instead.  Only versions prior to 2.3.185 are
    affected by this vulnerability. (CVE-2011-2039)

  - Unprivileged users can elevate to LocalSystem privileges
    by enabling the Start Before Logon feature and
    performing unspecified actions with the Cisco AnyConnect
    Secure Mobility client interface in the Windows logon
    screen. (CVE-2011-2041)"
  );
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=909
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6072ec79");
  # http://www.cisco.com/en/US/products/csa/cisco-sa-20110601-ac.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?06c90443");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 2.3.254 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cisco AnyConnect VPN Client ActiveX URL Property Download and Execute');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies('cisco_anyconnect_vpn_installed.nasl');
  script_require_keys('SMB/cisco_anyconnect/NumInstalled');

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

appname = 'Cisco AnyConnect VPN Client';
kb_base = 'SMB/cisco_anyconnect/';
report = '';

num_installed = get_kb_item_or_exit(kb_base + 'NumInstalled');

for (install_num = 0; install_num < num_installed; install_num++)
{
  path = get_kb_item_or_exit(kb_base + install_num + '/path');
  ver = get_kb_item_or_exit(kb_base + install_num + '/version');
  fix = '2.3.254.0';

  if (ver =~ "^2\." && ver_compare(ver:ver, fix:fix) < 0)
  {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + ver +
        '\n  Fixed version     : ' + fix + '\n';
  }
}

if(report != '')
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
    security_hole(port:445, extra:report);
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname);
