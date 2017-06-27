#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66023);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/04/18 13:25:07 $");

  script_cve_id("CVE-2013-1172", "CVE-2013-1173");
  script_bugtraq_id(59034, 59036);
  script_osvdb_id(92218, 92219);
  script_xref(name:"CISCO-BUG-ID", value:"CSCud14143");
  script_xref(name:"CISCO-BUG-ID", value:"CSCud14153");

  script_name(english:"Cisco AnyConnect Secure Mobility Client 2.x / 3.x < 3.1(3103) Host Scan Multiple Vulnerabilities");
  script_summary(english:"Checks version of Cisco AnyConnect Client");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has software installed that is potentially affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of Cisco AnyConnect 2.x or 3.x prior to
3.1(3103).  It is, therefore, potentially affected by the following
vulnerabilities :

  - A heap-based buffer overflow error exists in the file
    'ciscod.exe'. (CVE-2013-1173 / CSCud14143)

  - An unspecified error exists that could allow local
    privilege escalation attacks.
    (CVE-2013-1172 / CSCud14153)

Note that these issues affect only hosts with the 'Host Scan' component
deployed."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-1172
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?301ae033");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-1173");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ffd9a928");
  # http://tools.cisco.com/Support/BugToolKit/search/getBugDetails.do?method=fetchBugDetails&bugId=CSCud14143
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?78166e60");
  # http://tools.cisco.com/Support/BugToolKit/search/getBugDetails.do?method=fetchBugDetails&bugId=CSCud14153
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30cb663c");
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to Cisco AnyConnect Secure Mobility Client 3.1(3103) or
later."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

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
  fix = '3.1.3103.0';
  fix_display = fix + ' (3.1(3103))';

  if (
    ver =~ "^2\." ||
    (ver =~ "^3\." && ver_compare(ver:ver, fix:fix) == -1)
  )
  {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + ver +
        '\n  Fixed version     : ' + fix_display + '\n';
  }
}

if (report != '')
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0) security_warning(port:port, extra:report);
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname);
