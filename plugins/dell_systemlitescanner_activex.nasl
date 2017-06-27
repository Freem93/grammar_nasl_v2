#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(52045);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/28 03:40:59 $");
  
  script_cve_id("CVE-2011-0329", "CVE-2011-0330");
  script_bugtraq_id(46443);
  script_osvdb_id(72534, 72535);
  script_xref(name:"Secunia", value:"42880");

  script_name(english:"Dell DellSystemLite.Scanner ActiveX Control Multiple Vulnerabilities");
  script_summary(english:"Checks for the control");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by
multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The DellSystemLite.Scanner ActiveX control, a component from Dell to
determine relevant software for your system, installed on the remote
Windows host reportedly is affected by multiple vulnerabilities :

  - An input validation error exists in the 'GetData()' 
    method can be exploited to disclose the contents of
    arbitrary text files via directory traversal specifiers
    passed to the 'fileID' parameter.

  - The unsafe property 'WMIAttributesOfInterest' allows
    assigning arbitrary WMI Query Language statements that
    can be exploited to disclose system information.");

  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2011-10/");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2011-11/");
  script_set_attribute(attribute:"solution", value:"Remove or disable the control as fixes are not available.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:dell:dellsystemlite.scanner_activex_control");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
if (activex_init() != ACK_OK) exit(1, "activex_init() failed.");

clsid = '{C1F8FC10-E5DB-4112-9DBF-6C3FF728D4E3}';

file = activex_get_filename(clsid:clsid);
if (isnull(file))
{
  activex_end();
  exit(1, "activex_get_filename() returned NULL.");
}
if (!file)
{
  activex_end();
  exit(0, "The control is not installed as the class id '"+clsid+"' does not exist on the remote host.");
}

# Get its version.
version = activex_get_fileversion(clsid:clsid);
if (!version) version = 'unknown';


# And check it.
info = '';

if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
{
  info += 
    '\n  Class identifier  : ' + clsid +
    '\n  Filename          : ' + file +
    '\n  Installed version : ' + version + '\n';
}
activex_end();

# Report findings.
if (info)
{
  if (report_paranoia > 1)
  {
    report = info +
      '\n' +
      '\nNote, though, that Nessus did not check whether the kill bit was set' +
      '\nfor the control\'s CLSID because of the Report Paranoia setting in' +
      '\neffect when this scan was run.\n';
  }
  else
  {
    report = info +
      '\n' +
      '\nMoreover, its kill bit is not set so it is accessible via Internet' +
      '\nExplorer.\n';
  }

  if (report_verbosity > 0) security_warning(port:kb_smb_transport(), extra:report);
  else security_warning(kb_smb_transport());
  exit(0);
}
else exit(0, "The control is installed but its kill bit is set.");
