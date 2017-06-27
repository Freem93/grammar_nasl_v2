#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81671);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/06 18:37:09 $");

  script_cve_id("CVE-2014-8021");
  script_bugtraq_id(72475);
  script_osvdb_id(117894);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq80149");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup82990");

  script_name(english:"Cisco AnyConnect Secure Mobility Client < 3.1(6068) XSS");
  script_summary(english:"Checks the version of the Cisco AnyConnect client.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Cisco AnyConnect installed that is
prior to version 3.1.6073.0. It is, therefore, affected by a
cross-site scripting vulnerability due to improper validation of
user-supplied input when building a path for an applet in a Document
Object Model. An attacker can exploit this issue to execute arbitrary
script code in the browser of an unsuspecting user in the context of
the affected site.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-8021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5cd9741");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cisco AnyConnect Secure Mobility Client 3.1(6068) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_anyconnect_vpn_installed.nasl");
  script_require_keys("installed_sw/Cisco AnyConnect Secure Mobility Client", "SMB/Registry/Enumerated");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_name = "Cisco AnyConnect Secure Mobility Client";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
path = install['path'];
ver  = install['version'];

fix = '3.1.6068.0';
fix_display = fix + ' (3.1(6068))';

if (ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  set_kb_item(name: 'www/0/XSS', value: TRUE);

  if (report_verbosity > 0)
  {
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix_display +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, ver, path);
