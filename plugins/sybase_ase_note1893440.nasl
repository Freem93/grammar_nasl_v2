#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70975);
  script_version("$Revision: 1.5 $");   
  script_cvs_date("$Date: 2016/08/16 14:42:20 $");

  script_bugtraq_id(63549);
  script_osvdb_id(99129);
  script_xref(name:"IAVA", value:"2013-A-0217");

  script_name(english:"SAP Sybase Adaptive Server Enterprise SQL Injection (SAP Note 1893440)");
  script_summary(english:"Checks sqlserver.exe version");

  script_set_attribute(attribute:"synopsis", value:
"The version of SAP Sybase Adaptive Server Enterprise (ASE) installed on
the remote host is affected by a SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"SAP Sybase Adaptive Server Enterprise (ASE) contains a flaw that may
allow an attacker to carry out a SQL injection attack.  The issue is due
to the program not properly sanitizing user-supplied input before using
it in SQL queries.  This may allow an attacker to inject or manipulate
SQL queries in the back-end database, allowing for the manipulation or
disclosure of arbitrary data.");
  script_set_attribute(attribute:"see_also", value:"https://service.sap.com/sap/support/notes/1893440");
  script_set_attribute(attribute:"see_also", value:"http://www.sybase.com/detail?id=1099371");
  script_set_attribute(attribute:"solution", value:"Apply one of the patches listed in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sybase:adaptive_server_enterprise");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("sybase_ase_installed.nbin");
  script_require_keys("SMB/Sybase_ASE/Installed");   

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


kb = "SMB/Sybase_ASE/";
get_kb_item_or_exit(kb + "Installed");

path = get_kb_item_or_exit(kb + "Path");
ver  = get_kb_item_or_exit(kb + "Version");
ebf  = get_kb_item_or_exit(kb + "EBF");
arch = get_kb_item_or_exit(kb + "Architecture");

######################################################################
# This issue has been fixed in the following SAP Sybase ASE versions:
#
# Platform: Windows x64
#     EBF 21150: 15.7   SP100
#     EBF 20951: 15.7   ESD #4.2
#     EBF 21262: 15.5   ESD #5.3
#     EBF 21293: 15.0.3 ESD #4.3
#
# Platform: Windows x86
#     EBF 21149: 15.7   SP100
#     EBF 20950: 15.7   ESD #4.2
#     EBF 21261: 15.5   ESD #5.3
#     EBF 21286: 15.0.3 ESD #4.3
######################################################################

if (ver =~ "^15\.7([^0-9]|$)")
{
  # Choose the lowest EBF on this branch.
  ver_fix = "15.7 ESD #4.2";
  if (arch == "x64")
    ebf_fix = 20951;
  else
    ebf_fix = 20950;
}
else if (ver =~ "^15\.5([^0-9]|$)")
{
  # Choose the lowest EBF on this branch.
  ver_fix = "15.5 ESD #5.3";
  if (arch == "x64")
    ebf_fix = 21262;
  else
    ebf_fix = 21261;
}
else if (ver =~ "^15\.0\.3([^0-9]|$)")
{
  # Choose the lowest EBF on this branch.
  ver_fix = "15.0.3 ESD #4.3";
  if (arch == "x64")
    ebf_fix = 21293;
  else
    ebf_fix = 21286;
}

if (isnull(ebf_fix) || ebf >= ebf_fix)
  audit(AUDIT_INST_PATH_NOT_VULN, "SAP Sybase ASE", ver, path);

set_kb_item(name:'www/0/SQLInjection', value:TRUE);

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + ver_fix +
    '\n';
}

port = get_kb_item("SMB/transport");
if (!port) port = 445;

security_hole(port:port, extra:report);