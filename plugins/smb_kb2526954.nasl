#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53830);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2012/02/21 18:30:13 $");

  script_cve_id("CVE-2011-1844", "CVE-2011-1845");
  script_bugtraq_id(47724);
  script_osvdb_id(75269, 75271);

  script_name(english:"MS KB2526954: Microsoft Silverlight 4.0 < 4.0.60310 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Microsoft Silverlight");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a browser plug-in that is affected by
multiple memory leaks.");

  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of Microsoft Silverlight
that is affected by multiple vulnerabilities :

  - A memory leak exists relating to a popup control and a
    custom 'DependencyProperty' property. (CVE-2011-1844)

  - Multiple memory leaks exist in the 'DataGrid' control 
    implementation. (CVE-2011-1845)");

  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/2526954");
  script_set_attribute(attribute:"solution", value:"Upgrade to Silverlight 4.0.60310.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "silverlight_detect.nasl");
  script_require_keys("SMB/Silverlight/Version");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit('SMB/Silverlight/Version');
fix = '4.0.60310.0';

if (version =~ '^4\\.0\\.' && ver_compare(ver:version, fix:fix) == -1)
{
  path = get_kb_item('SMB/Silverlight/Path');
  if (isnull(path)) path = 'n/a';

  if (report_verbosity > 0)
  {
    report += 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(port:get_kb_item('SMB/transport'));
  exit(0);
}
else exit(0, 'The host is not affected because Silverlight version '+version+' is installed.');
