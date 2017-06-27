#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72211);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/05/24 02:20:54 $");

  script_cve_id("CVE-2011-5154");
  script_bugtraq_id(46857);
  script_osvdb_id(71411);

  script_name(english:"SAP GUI DLL Loading Arbitrary Code Execution (Note 1511179)");
  script_summary(english:"Checks the version of SAP GUI.");

  script_set_attribute(attribute:"synopsis", value:
"A program installed on the remote Windows host is affected by an
insecure DLL loading vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of SAP GUI that reportedly
insecurely looks in its current working directory when resolving DLLs
such as 'MFC80LOC.DLL' and 'MFC80RUS.DLL'.");
  script_set_attribute(attribute:"see_also", value:"http://dsecrg.com/pages/vul/show.php?id=314");
  script_set_attribute(attribute:"see_also", value:"https://service.sap.com/sap/support/notes/1511179");
  script_set_attribute(attribute:"solution", value:"Upgrade to SAP GUI version 7.20 SP3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/30");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:gui");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("sap_gui_detect.nasl");
  script_require_keys("Settings/ParanoidReport", "SMB/SAP_GUI/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Pull the installation information from the KB.
base = get_kb_item_or_exit("SMB/SAP_GUI/Path");
ver = get_kb_item_or_exit("SMB/SAP_GUI/Version");

# Prevent potential false positives.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Determine if the version is vulnerable.
fix = "7200.1.3.8945";
if (
  ver_compare(ver:ver, fix:"6400", strict:FALSE) < 0 ||
  ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0
) audit(AUDIT_INST_PATH_NOT_VULN, "SAP GUI", ver, base);

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + base +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
}

port = get_kb_item("SMB/transport");
if (isnull(port)) port = 445;

security_warning(port:port, extra:report);
