#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49174);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2012/09/07 18:22:25 $");

  script_cve_id("CVE-2010-5227");
  script_bugtraq_id(42663);
  script_osvdb_id(67498);
  script_xref(name:"EDB-ID", value:"14732");
  script_xref(name:"Secunia", value:"41083");

  script_name(english:"Opera < 10.62 Path Subversion Arbitrary DLL Injection Code Execution");
  script_summary(english:"Checks version number of Opera");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that allows arbitrary code
execution.");
  script_set_attribute(attribute:"description", value:

"The version of Opera installed on the remote host is earlier than
10.62.  Such versions insecurely look in their current
working directory when resolving DLL dependencies, such as for
'dwmapi.dll'

If another application can be made to launch Opera in such a way that
it searches for DLLs in the same location as a resource that is being
loaded, it will allow remote code execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/1062/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/970/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Opera 10.62 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/10");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Opera/Version");

version_ui = get_kb_item("SMB/Opera/Version_UI");
if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

install_path = get_kb_item('SMB/Opera/Path');

if (ver_compare(ver:version, fix:'10.62.3500.0') == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + install_path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : 10.62\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(port:get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, "The host is not affected since Opera "+version_report+" is installed.");
