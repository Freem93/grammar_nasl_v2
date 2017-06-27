#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69872);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_cve_id(
    "CVE-2004-0230",
    "CVE-2005-2798",
    "CVE-2006-0225",
    "CVE-2006-4924",
    "CVE-2006-5051",
    "CVE-2010-1169",
    "CVE-2010-1170",
    "CVE-2010-1447",
    "CVE-2010-3433",
    "CVE-2010-4015"
  );
  script_bugtraq_id(
    10183,
    14729,
    16369,
    20216,
    20241,
    40215,
    40305,
    43747,
    46084
  );
  script_osvdb_id(
    13619,
    19141,
    22692,
    29152,
    29264,
    4030,
    64755,
    64756,
    64757,
    68436,
    70740
  );

  script_name(english:"Juniper NSM Servers < 2012.1 Multiple Vulnerabilities");
  script_summary(english:"Checks versions of NSM servers");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the version of one or more Juniper NSM servers running on
the remote host, it is potentially vulnerable to multiple
vulnerabilities, the worst of which may allow an authenticated user to
trigger a denial of service condition or execute arbitrary code."
  );
  # http://kb.juniper.net/InfoCenter/index?page=content&legacyid=PSN-2012-08-686
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dbe774be");
  # http://kb.juniper.net/InfoCenter/index?page=content&legacyid=PSN-2012-08-687
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fcb7ea7f");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to NSM version 2012.1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(362, 399);
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/03");
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
  report_str2 = "Fixed Version             : ";
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

# fix : NSM version 2012.1 or later
item = eregmatch(pattern:"^([0-9.]+)", string:version);
if (!isnull(item))
{
  fix = '2012.1';
  if (ver_compare(ver:item[1], fix:fix, strict:FALSE) == -1)
  {
    report += '\n  ' + report_str1 + disp_version +
              '\n  ' + report_str2 + '2012.1' + '\n';
  }
}

if (report == '') audit(AUDIT_INST_VER_NOT_VULN, "Juniper NSM GUI Server or Device Server");

if (report_verbosity > 0) security_hole(extra:report, port:port);
else security_hole(port);
