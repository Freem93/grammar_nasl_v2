#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16314);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2015/10/21 20:34:21 $");

  script_name(english:"Microsoft Windows SMB : Suspicious Software Detection");
  script_summary(english:"Checks for the presence of various DLLs on the remote host.");

  script_set_attribute(attribute:'synopsis', value:
"This plugin checks for known suspicious files.");
  script_set_attribute(attribute:'description', value:
"This plugin checks for the presence of files and programs which might
have been installed without user consent.");
  script_set_attribute(attribute:'solution', value:
"Verify if the applications found are compliant with your
organization's security policy.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
  script_family(english:"Windows");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

include("audit.inc");
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_com_func.inc');
include('misc_func.inc');
include('suspicious_files.inc');

get_kb_item_or_exit("SMB/Registry/Enumerated");

code = 0;

code = check_reg_clsids();

if (code != 0)
  exit(1, 'Failed to check CLSIDs with an error code of ' + code);

code = check_root_files();

if (code != 0)
  exit(1, 'Failed to check root files with an error code of ' + code);

report = get_report();

if(report[0] == 0)
{
  security_hole(port:kb_smb_transport(), extra:report[1]);
}
else audit(AUDIT_HOST_NOT, 'affected');
