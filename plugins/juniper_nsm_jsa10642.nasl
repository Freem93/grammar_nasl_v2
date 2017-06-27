#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77326);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id(
    "CVE-2011-0419",
    "CVE-2011-3192",
    "CVE-2011-3368",
    "CVE-2012-0031",
    "CVE-2012-0053",
    "CVE-2012-5081",
    "CVE-2013-0169",
    "CVE-2013-0440",
    "CVE-2013-0443",
    "CVE-2013-1537",
    "CVE-2013-2407",
    "CVE-2013-2451",
    "CVE-2013-2457",
    "CVE-2013-2461",
    "CVE-2013-4002",
    "CVE-2013-5780",
    "CVE-2013-5802",
    "CVE-2013-5803",
    "CVE-2013-5823",
    "CVE-2013-5825",
    "CVE-2013-5830",
    "CVE-2014-0411",
    "CVE-2014-0423",
    "CVE-2014-0453",
    "CVE-2014-0460"
  );
  script_bugtraq_id(
    47820,
    49303,
    49957,
    51407,
    51706,
    56071,
    57670,
    57702,
    57712,
    57778,
    59194,
    60625,
    60645,
    60653,
    61310,
    63082,
    63110,
    63115,
    63121,
    63135,
    64914,
    64918,
    66914,
    66916
  );
  script_osvdb_id(
    73383,
    73388,
    74721,
    76079,
    78293,
    78556,
    86369,
    89802,
    89804,
    89848,
    92343,
    94350,
    94352,
    94362,
    94373,
    95418,
    98544,
    98550,
    98551,
    98562,
    98569,
    98572,
    102008,
    102028,
    105889,
    105897
  );
  script_xref(name:"CERT", value:"737740");
  script_xref(name:"CERT", value:"858729");

  script_name(english:"Juniper NSM < 2012.2R9 Multiple Java and Apache Vulnerabilities (JSA10642)");
  script_summary(english:"Checks the versions of NSM servers.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has one or more instances of NSM (Network and Security
Manager) Server running, with version(s) prior to 2012.2R9. It is,
therefore, affected by multiple vulnerabilities related to its Java
and Apache installations.");

  # http://www.juniper.net/techpubs/software/management/security-manager/nsm2012_2/nsm2012_2_release_notes.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d05776a");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10642");
  script_set_attribute(attribute:"solution", value:"Upgrade to NSM version 2012.2R9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:network_and_security_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl","juniper_nsm_gui_svr_detect.nasl","juniper_nsm_servers_installed.nasl");
  script_require_keys("Juniper_NSM_VerDetected");
  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");

kb_base = "Host/NSM/";

# No Solaris download available according to the Vendor's advisory
os = get_kb_item("Host/OS");
if (report_paranoia < 2)
{
  if (!isnull(os) && 'Solaris' >< os) audit(AUDIT_HOST_NOT, 'affected');
}

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

# NSM 2012.2R9 or later
# replace r or R with . for easier version comparison
# in 2010 and 2011 versions they use S instead of R
version_num = ereg_replace(pattern:"(r|R|s|S)", replace:".", string:version);

# remove trailing . if it exists
version_num = ereg_replace(pattern:"\.$", replace:"", string:version_num);

fix_disp = "2012.2R9";
fix_num = "2012.2.9";
if (ver_compare(ver:version_num, fix:fix_num, strict:FALSE) < 0)
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
