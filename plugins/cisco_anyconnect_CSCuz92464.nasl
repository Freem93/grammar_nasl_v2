#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93382);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/21 15:06:14 $");

  script_cve_id("CVE-2016-6369");
  script_bugtraq_id(92625);
  script_osvdb_id(143432);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160824-anyconnect");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz92464");

  script_name(english:"Cisco AnyConnect Secure Mobility Client 4.2.x < 4.2.5015.0 / 4.3.x < 4.3.2039.0 Privilege Escalation Vulnerability");
  script_summary(english:"Checks the version of the Cisco AnyConnect client.");

  script_set_attribute(attribute:"synopsis", value:
"A VPN application installed on the remote host is affected by a
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco AnyConnect Secure Mobility Client installed on
the remote Windows host is 4.2.x prior to 4.2.5015.0 or 4.3.x prior
to 4.3.2039.0. It is, therefore, affected by a privilege escalation
vulnerability due to incomplete validation of path names and file
names at installation time. A local attacker can exploit this, via a
specially crafted INF file, to install and execute files on the
underlying host with SYSTEM level privileges.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160824-anyconnect
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d67b10be");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuz92464");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco AnyConnect Secure Mobility Client version
4.2.5015.0 / 4.3.2039.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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

fix = '';

if (ver =~ "^4\.3\." && (ver_compare(ver:ver, fix:'4.3.2039.0', strict:FALSE) < 0))
  fix = '4.3.2039.0';

else if (ver_compare(ver:ver, fix:'4.2.5015.0', strict:FALSE) < 0)
  fix = '4.2.5015.0';

if (!empty(fix))
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, ver, path);
