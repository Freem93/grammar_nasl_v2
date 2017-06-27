#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29747);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2014/04/17 18:47:26 $");

  script_cve_id("CVE-2007-6506");
  script_bugtraq_id(26950);
  script_osvdb_id(40237, 40238);

  script_name(english:"HP Software Update HPRulesEngine.ContentCollection ActiveX (RulesEngine.dll) Multiple Insecure Methods");
  script_summary(english:"Checks whether kill bit is set for HP Rules Processing Engine ActiveX control"); 
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that allows reading and
writing of arbitrary files." );
  script_set_attribute(attribute:"description", value:
"The remote host contains the HP Software Update software, installed by
default on many HP notebooks to support automatic software updates and
vulnerability patching. 

The version of this software on the remote host includes an ActiveX
control, 'RulesEngineLib', that reportedly contains two insecure
methods - 'LoadDataFromFile()' and 'SaveToFile()' - that are marked as
'Safe for Scripting' and allow for reading and overwriting arbitrary
files on the affected system.  If a remote attacker can trick a user
on the affected host into visiting a specially crafted web page, this
issue could be leveraged to effectively destroy arbitrary files on the 
remote host, potentially even files that are vital for its operation, 
or to read the contents of arbitrary files." );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/485325/30/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/13673" );
  script_set_attribute(attribute:"solution", value:
"Either use HP Software Update itself to update the software or disable
use of this ActiveX control from within Internet Explorer by setting
its kill bit." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value: "2007/12/23");
  script_set_attribute(attribute:"patch_publication_date", value: "2007/12/21");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:software_update");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


get_kb_item_or_exit("SMB/Registry/Enumerated");


# Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");

clsid = "{7CB9D4F5-C492-42A4-93B1-3F7D6946470D}";
file = activex_get_filename(clsid:clsid);
activex_end();

if (file)
{
  if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
  {
    if (report_verbosity > 0)
    {
      report = 
        '\n  Class Identifier  : ' + clsid +
        '\n  Filename          : ' + file + '\n';

      if (report_paranoia > 1)
        report = strcat(
          report,
          '\n',
          'Note, though, that Nessus did not check whether the kill bit was\n',
          'set for the control\'s CLSID because of the Report Paranoia setting\n',
          'in effect when this scan was run.\n'
        );
      else
        report = strcat(
          report,
          '\n',
          'Moreover, its kill bit is not set so it is accessible via Internet\n',
          'Explorer.\n'
        );

      security_hole(port:kb_smb_transport(), extra:report);
    }
    else security_hole(kb_smb_transport());
    exit(0);
  }
  else exit(0, "The control is installed as "+file+", but its kill bit is set.");
}
else exit(0, "The control is not installed.");
