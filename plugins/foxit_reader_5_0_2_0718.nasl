#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55671);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/10/10 15:57:05 $");

  script_cve_id("CVE-2011-3691");
  script_bugtraq_id(48836);
  script_osvdb_id(74315, 74316);
  script_xref(name:"EDB-ID", value:"11196");

  script_name(english:"Foxit Reader < 5.0.2.0718 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Foxit Reader.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Foxit Reader installed on the remote Windows host is
prior to 5.0.2.0718. It is, therefore, affected by multiple
vulnerabilities :

  - A flaw exists in how dynamic-link library (DLL) files
    are located and loaded, specifically files dwmapi.dll,
    dwrite.dll, and msdrm.dll. The application uses a fixed
    path to search for these files, and the path can include
    directories that may not be trusted or under the user's
    control. An attacker can exploit this issue, via a
    crafted Trojan horse DLL file injected into the search
    path, to execute arbitrary code with the privileges of
    the application or the user executing the application.
    (CVE-2011-3691)
    
  - A boundary error exists in the FoxitReaderOCX ActiveX
    control in the OpenFile() method due to improper
    sanitization of user-supplied input. An attacker can
    exploit this, via an overly long string passed to the
    'strFilePath' parameter, to execute arbitrary code.
    (VulnDB 74315)");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2011-55/");
  # https://www.solutionary.com/threat-intelligence/vulnerability-disclosures/2011/07/foxit-reader-insecure-library-loading/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ffc67b9");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Jul/139");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/company/press.php?id=224");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit Reader version 5.0.2.0718 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:foxitsoftware:foxit_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("foxit_reader_installed.nasl");
  script_require_keys("installed_sw/Foxit Reader");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "Foxit Reader";
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
version = install["version"];
path    = install["path"];

report = NULL;

fixed_version = "5.0.2.0718";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port)
    port = 445;

  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version + '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
