#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69874);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_cve_id(
    "CVE-2008-3103",
    "CVE-2008-3104",
    "CVE-2008-3105",
    "CVE-2008-3106",
    "CVE-2008-3107",
    "CVE-2008-3108",
    "CVE-2008-3109",
    "CVE-2008-3110",
    "CVE-2008-3111",
    "CVE-2008-3112",
    "CVE-2008-3113",
    "CVE-2008-3114",
    "CVE-2008-3115",
    "CVE-2011-0786",
    "CVE-2011-0802",
    "CVE-2011-0814",
    "CVE-2011-0815",
    "CVE-2011-0817",
    "CVE-2011-0862",
    "CVE-2011-0863",
    "CVE-2011-0864",
    "CVE-2011-0865",
    "CVE-2011-0866",
    "CVE-2011-0867",
    "CVE-2011-0868",
    "CVE-2011-0869",
    "CVE-2011-0871",
    "CVE-2011-0872",
    "CVE-2011-0873"
  );
  script_bugtraq_id(
    30140,
    30141,
    30143,
    30144,
    30146,
    30147,
    30148,
    48133,
    48134,
    48136,
    48137,
    48138,
    48139,
    48140,
    48141,
    48142,
    48143,
    48144,
    48145,
    48146,
    48147,
    48148,
    48149
  );
  script_osvdb_id(
    46955,
    46956,
    46957,
    46958,
    46959,
    46960,
    46961,
    46962,
    46963,
    46964,
    46965,
    46966,
    46967,
    73069,
    73070,
    73071,
    73072,
    73073,
    73074,
    73075,
    73076,
    73077,
    73078,
    73080,
    73081,
    73082,
    73083,
    73084,
    73085,
    73176
  );

  script_name(english:"Juniper NSM Servers Multiple Java JDK/JRE Vulnerabilities (PSN-2012-08-689)");
  script_summary(english:"Checks versions of NSM servers");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the version of one or more Juniper NSM servers running on
the remote host, it is potentially affected by multiple vulnerabilities
affecting the Java software running on the host."
  );
  # http://kb.juniper.net/InfoCenter/index?page=content&legacyid=PSN-2012-08-689
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e9601ccb");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to NSM version 2012.1R2, 2011.4s5, or 2010.3s8."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(16, 20, 119, 200, 264);
  script_set_attribute(attribute:"vuln_publication_date", value:"2008/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/13");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:netscreen-security_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("juniper_nsm_gui_svr_detect.nasl", "juniper_nsm_servers_installed.nasl");
  script_require_keys("Juniper_NSM_VerDetected");
  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");

kb_base = "Host/NSM/";

get_kb_item_or_exit("Juniper_NSM_VerDetected");

kb_list = make_list();

temp = get_kb_list("Juniper_NSM_GuiSvr/*/build");

if (!isnull(temp) && max_index(keys(temp)) > 0)
  kb_list = make_list(kb_list, keys(temp));

temp = get_kb_list("Host/NSM/*/build");
if (!isnull(temp) && max_index(keys(temp)) > 0)
  kb_list = make_list(kb_list, keys(temp));

if (isnull(kb_list)) audit(AUDIT_NOT_INST, "Juniper NSM Servers");

report = '';

entry = branch(kb_list);

port = 0;
kb_base = '';

if ("Juniper_NSM_GuiSvr" >< entry)
{
  port = entry - "Juniper_NSM_GuiSvr/" - "/build";
  kb_base = "Juniper_NSM_GuiSvr/" + port + "/";

  report_str1 = "Remote GUI server version : ";
  report_str2 = "Fixed version             : ";
}
else
{
  kb_base = entry - "build";
  if ("guiSvr" >< kb_base)
  {
    report_str1 = "Local GUI server version : ";
    report_str2 = "Fixed version            : ";
  }
  else
  {
    report_str1 = "Local device server version : ";
    report_str2 = "Fixed version               : ";
  }
}

build = get_kb_item_or_exit(entry);
version = get_kb_item_or_exit(kb_base + 'version');

disp_version = version + " (" + build + ")";

#  NSM version 2012.1R2 or later
#  NSM version 2011.4s5 or later
#  NSM version 2010.3s8 or later
item = eregmatch(pattern:"^([0-9.]+)", string:version);

if (!isnull(item))
{
  if (
    ver_compare(ver:item[1], fix:'2010.3', strict:FALSE) == -1 ||
    version =~ "^2010.3([rR][1-2]|[sS][1-7])?$"
  )
  {
    report += '\n  ' + report_str1 + disp_version +
              '\n  ' + report_str2 + '2010.3s8' + '\n';
  }
  if (
    (version =~ "^2011\." &&
    ver_compare(ver:item[1], fix:'2011.4', strict:FALSE) == -1) ||
    version =~ "^2011.4([sS][1-4])?$"
  )
  {
    report += '\n  ' + report_str1 + disp_version +
              '\n  ' + report_str2 + '2011.4s5' + '\n';
  }
  if (version =~ "^2012\.(1|1[rR]1)$")
  {
    report += '\n  ' + report_str1 + disp_version +
              '\n  ' + report_str2 + '2012.1R2' + '\n';
  }
}

if (report == '') audit(AUDIT_INST_VER_NOT_VULN, "Juniper NSM GUI Server or Device Server");

if (report_verbosity > 0)
  security_hole(extra:report, port:port);
else security_hole(port);
