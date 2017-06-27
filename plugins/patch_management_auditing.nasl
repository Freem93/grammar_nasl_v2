#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if ( NASL_LEVEL < 3000 ) exit(0);

if (description)
{
  script_id(64294);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/11/22 22:47:55 $");

  script_name(english: "Patch Management Windows Auditing Conflicts");
  script_summary(english:"Compare reporting for patch management and Nessus.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin compares the reported vulnerable Windows patches to 
find conflicts.");
  script_set_attribute(attribute:"description", value:
"This plugin compares vulnerabilities reported by Nessus and supplied 
patch management results to determine conflicts in Windows patches. 
The report will allow you to audit your patch management solution to 
determine if it is reporting properly.");
  script_set_attribute(attribute:"solution", value:"If conflicts exist, they should be resolved with updates.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"General");
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("smb_missing_msft_patches.nasl");
  if ( NASL_LEVEL >= 5200 ) script_dependencies("pluginrules.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "patch_management/ran");
  exit(0);
}

include("smb_hotfixes.inc");
include("plugin_feed_info.inc");

pm_bulletins = make_array();
pm_tools = make_array();

# generate nessus missing patch list
if (!isnull(get_kb_list("SMB/Registry/Enumerated")))
{
  bulletin_list = get_kb_list("SMB/Missing/*");
  if (!isnull(bulletin_list))
  {
    foreach bulletin (keys(bulletin_list)) 
    {
      bulletin -= "SMB/Missing/";
      pm_bulletins[tolower(bulletin)] = TRUE;
    }
  }
  pm_tools["Nessus"] = pm_bulletins;
}

# generate patch management missing list
foreach tool (keys(_pmtool_names))
{
  if (isnull(get_kb_item("patch_management/"+tool))) continue;

  pm_bulletins = make_array();
  bulletin_list = get_kb_list(tool+"/missing_patch/nt/bulletin/*");
  if (!isnull(bulletin_list))
  {
    foreach bulletin (keys(bulletin_list)) 
    {
      bulletin -= tool+"/missing_patch/nt/bulletin/";
      pm_bulletins[tolower(bulletin)] = TRUE;
    }
  }
  pm_tools[_pmtool_names[tool]] = pm_bulletins;
}

# generate report
report = '';

# report conflicts
foreach key (keys(pm_tools))
{
  tool_bulletins1 = pm_tools[key];
  foreach tool (keys(pm_tools))
  {
    if (tool == key) continue;

    report_builder = "";
    tool_bulletins2 = pm_tools[tool];
    foreach bulletin1 (sort(keys(tool_bulletins1)))
    {
      if (isnull(tool_bulletins2[bulletin1]))
      {
        report_builder += "  " + bulletin1 + " : " + key + ' reports vulnerable , ' + tool + ' is NOT reporting vulnerable\n';
      }
    }

    if (strlen(report_builder) > 0)
    {
      report += '\n'+key+' -> '+tool+' conflicts\n';
      report += report_builder;
    }
  }
}

count = 0; #used to detect the number of patch management solutions
tool_report = "";
foreach key (keys(pm_tools))
{
  count++;
  tool_report += key + '\n';
}
if (count < 2) 
  exit(0, "There are fewer than two patch management solutions available; at least two are needed to compare.");

if (strlen(report) > 0)
{
  # report last update for each tool used
  nessusTimestamp += '\nNessus feed : ' + PLUGIN_SET + '\n';

  tool_report = '\nThe following tools were used in this scan.\n' + tool_report;
  report = tool_report + nessusTimestamp + report;

  security_hole(port:0, extra:report);
}
else
{
  tool_report = str_replace(string:tool_report, find:'\n', replace:',' );
  set_kb_item(name:"patch_management/no/conflicts" ,value:tool_report);
}

