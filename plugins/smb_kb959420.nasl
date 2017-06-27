#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35635);
  script_version("$Revision: 1.28 $");
  script_cvs_date("$Date: 2016/12/09 20:54:59 $");

  script_cve_id("CVE-2008-5416");
  script_bugtraq_id(32710);
  script_osvdb_id(50589);
  script_xref(name:"IAVA", value:"2009-A-0012");
  script_xref(name:"MSFT", value:"MS09-004");
  script_xref(name:"CERT", value:"696644");
  script_xref(name:"EDB-ID", value:"7501");
  script_xref(name:"EDB-ID", value:"16392");
  script_xref(name:"EDB-ID", value:"16396");

  script_name(english:"MS09-004: Vulnerability in Microsoft SQL Server Could Allow Remote Code Execution (959420) (uncredentialed check)");
  script_summary(english:"Determines the version of SQL Server.");

  script_set_attribute(attribute:"synopsis", value:
"A database application installed on the remote host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of Microsoft SQL Server,
Desktop Engine, or Internal Database that is affected by a remote code
execution vulnerability in the sp_replwritetovarbin() stored procedure
due to a failure to check invalid parameters. An authenticated, remote
attacker can exploit this, via specially crafted request, to cause the
execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms09-004");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SQL Server 2000 and 2005.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS09-004 Microsoft SQL Server sp_replwritetovarbin Memory Corruption via SQL Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("mssqlserver_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports(1433, "Services/mssql");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app = "MSSQL Server";

port = get_service(svc:"mssql", default:1433, exit_on_fail:TRUE);
version = get_kb_item_or_exit("MSSQL/"+port+"/Version");

if (report_paranoia < 2) audit(AUDIT_PARANOID);
fix = '';

if (version =~ "^[89](\.0)?$")
  audit(AUDIT_VER_NOT_GRANULAR, app, port, version);

if ( version =~ "^8\.0\." )
  fix = "8.0.2055";
if ( version =~ "^9\.0\." )
  fix = "9.0.3077";

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report = '\n  Installed version : ' + version +
           '\n  Fixed version     : ' + fix +
           '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, app, port, version);
