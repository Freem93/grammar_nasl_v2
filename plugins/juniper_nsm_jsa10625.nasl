#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74140);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id("CVE-2014-3411");
  script_bugtraq_id(67445);
  script_osvdb_id(106938);

  script_name(english:"Juniper NSM Remote Code Execution (JSA10625)");
  script_summary(english:"Checks versions of NSM servers");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has one or more instances of NSM (Network and Security
Manager) Server running, with version(s) prior to 2012.2R8. It is,
therefore, affected by a remote code execution vulnerability in the
NSM XDB service.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10625");
  script_set_attribute(attribute:"solution", value:"Upgrade to NSM version 2012.2R8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:network_and_security_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

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

version_disp = version + " (" + build + ")";

# NSM 2012.2R8 or later
# replace r or R with . for easier version comparison
# in 2010 and 2011 versions they use S instead of R
version_num = ereg_replace(pattern:"(r|R|s|S)", replace:".", string:version);

# remove trailing . if it exists
version_num = ereg_replace(pattern:"\.$", replace:"", string:version_num);

fix_disp = "2012.2R8";
fix_num = "2012.2.8";
if (ver_compare(ver:version_num, fix:fix_num, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = '\n  ' + report_str1 + version_disp +
             '\n  ' + report_str2 + fix_disp +
             '\n';
    security_hole(extra:report, port:port);
  }
  else security_hole(port:port);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Juniper NSM", version_disp);
