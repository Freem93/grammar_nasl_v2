#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71464);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/04/27 19:46:26 $");

  script_cve_id("CVE-2013-5559");
  script_bugtraq_id(63491);
  script_osvdb_id(99258);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj58139");

  script_name(english:"Cisco AnyConnect Secure Mobility Client 2.x / 3.x < 3.0(629) ATL Buffer Overflow");
  script_summary(english:"Checks version of Cisco AnyConnect Client");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has software installed that is affected by a buffer
overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of Cisco AnyConnect 2.x or 3.x prior to
3.1(629).  As such, when the VPNAPI COM module calls the ATL framework,
certain input data are not properly validated and could allow a buffer
overflow.  This error could lead to arbitrary code execution."
  );
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuj58139");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-5559
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4524ecb");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=31606");
  # http://blogs.ixiacom.com/ixia-blog/newly-discovered-vulnerability-in-cisco-anyconnect/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?577a8ca4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco AnyConnect Secure Mobility Client 3.0(629) or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies('cisco_anyconnect_vpn_installed.nasl');
  script_require_keys('SMB/cisco_anyconnect/Installed');

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

appname = 'Cisco AnyConnect Mobility VPN Client';
kb_base = 'SMB/cisco_anyconnect/';
report = '';

num_installed = get_kb_item_or_exit(kb_base + 'NumInstalled');

for (install_num = 0; install_num < num_installed; install_num++)
{
  path = get_kb_item_or_exit(kb_base + install_num + '/path');
  ver = get_kb_item_or_exit(kb_base + install_num + '/version');
  fix = '3.0.629.0';
  fix_display = fix + ' (3.0(629))';

  if ((ver =~ "^2\." || ver =~ "^3\.0\.")  && ver_compare(ver:ver, fix:fix) == -1)
  {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + ver +
        '\n  Fixed version     : ' + fix_display + '\n';
  }
}

if (report != '')
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0) security_hole(port:port, extra:report);
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname);
