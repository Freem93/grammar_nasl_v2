#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55474);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/06/14 19:14:02 $");

  script_bugtraq_id(48385);
  script_osvdb_id(73233);
  script_xref(name:"IAVB", value:"2011-B-0084");

  script_name(english:"Citrix EdgeSight for Load Testing < 3.8.1 Remote Code Execution");
  script_summary(english:"Checks version of Citrix EdgeSight for Load Testing");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by a code execution vulnerability.");

  script_set_attribute(attribute:"description", value:
"According to its version number, the Citrix EdgeSight for Load
Testing install on the remote Windows host is earlier than 3.8.1.  As
such, it is affected by a code execution vulnerability in the
'LauncherService.exe' component.");

  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX129699");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-226/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Citrix EdgeSight for Load Testing 3.8.1 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/30");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:edgesight");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");

  script_dependencies("citrix_edgesight_installed.nasl");
  script_require_keys("SMB/Citrix EdgeSight for Load Testing/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit('SMB/Citrix EdgeSight for Load Testing/Version');
path    = get_kb_item_or_exit('SMB/Citrix EdgeSight for Load Testing/Path');


if (ver_compare(ver:version, fix:"3.8.1", strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.8.1.178\n';
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(get_kb_item('SMB/transport'));
  exit(0);
}
else exit(0, 'Citrix EdgeSight for Load Testing '+version+' is installed and thus not affected.');
