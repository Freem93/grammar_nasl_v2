#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69132);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/15 16:37:16 $");

  script_cve_id("CVE-2010-2826");
  script_bugtraq_id(42368);
  script_osvdb_id(67190);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtf37019");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20100811-wcs");

  script_name(english:"Cisco Wireless Control System SQL Injection (cisco-sa-20100811-wcs) (credentialed check)");
  script_summary(english:"Checks WCS version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A wireless management application installed on the remote host has a
SQL injection vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version, the version of Cisco Wireless
Control System installed on the remote host is 6.0.x before 6.0.196.0. 
Such versions have a SQL injection vulnerability.  A remote,
authenticated attacker could exploit this to modify the configuration of
WCS or any wireless devices managed by WCS."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/csa/cisco-sa-20100811-wcs.html");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Cisco Wireless Control System version 6.0.196.0 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:wireless_control_system_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_wcs_installed_win.nasl", "cisco_wcs_installed_linux.nasl");
  script_require_ports("SMB/cisco_wcs/version", "cisco_wcs/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_internals.inc");

installs = make_array();

# linux
port = 0;
versions = get_kb_list('cisco_wcs/version');
foreach ver (versions)
  installs[ver] = get_kb_item_or_exit('cisco_wcs/' + ver + '/path');

# windows
if (isnull(ver))
{
  port = kb_smb_transport();
  versions = get_kb_list('SMB/cisco_wcs/version');
  foreach ver (versions)
    installs[ver] = get_kb_item_or_exit('SMB/cisco_wcs/' + ver + '/path');
}

if (max_index(keys(installs)) == 0)
  audit(AUDIT_NOT_INST, 'Cisco WCS');

nonvuln = make_list();
report = NULL;

foreach ver (keys(installs))
{
  # the advisory says:
  # Cisco WCS devices running software 6.0.x are affected by this vulnerability.
  # This vulnerability is fixed in Cisco WCS version 6.0.196.0.
  fix = '6.0.196.0';
  if (ver =~ "^6\.0\." && ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
  {
    report +=
      '\n  Path              : ' + installs[ver] +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix + '\n';
  }
  else
  {
    nonvuln = make_list(nonvuln, ver);
  }
}

if (!isnull(report))
{
  if (report_verbosity > 0)
    security_hole(port:port, extra:report);
  else
    security_hole(port);
}

if (max_index(nonvuln) > 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco WCS', join(nonvuln, sep:'/'));

