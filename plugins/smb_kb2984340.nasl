#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77161);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 15:02:05 $");

  script_cve_id("CVE-2014-1820", "CVE-2014-4061");
  script_bugtraq_id(69071, 69088);
  #script_osvdb_id();
  script_xref(name:"MSFT", value:"MS14-044");
  script_xref(name:"IAVA", value:"2014-A-0126");

  script_name(english:"MS14-044: Vulnerability in SQL Server Could Allow Elevation of Privilege (2984340) (uncredentialed check)");
  script_summary(english:"Determines the version of the SQL Server.");

  script_set_attribute(attribute:"synopsis", value:
"A cross-site scripting vulnerability in SQL Server could allow an
elevation of privilege.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Microsoft SQL Server installed. This
version of SQL Server is potentially affected by multiple
vulnerabilities :

  - A cross-site scripting vulnerability exists in the
    SQL Master Data Services. (CVE-2014-1820)

  - A denial of service vulnerability exists in SQL Server.
    (CVE-2014-4061)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS14-044");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SQL Server 2008, 2008 R2,
2012, and 2014.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("mssqlserver_detect.nasl");
  script_require_ports(1433, "Services/mssql");
  script_require_keys("Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

port = get_service(svc:"mssql", exit_on_fail:TRUE);
pcidss = get_kb_item("Settings/PCI_DSS");

ver = get_kb_item("MSSQL/" + port + "/Version");
if (!ver) audit(AUDIT_SERVICE_VER_FAIL,"MSSQL", port);

v = split(ver, sep:".", keep:FALSE);

if (
  # 2008 < SP3
  (pcidss && (int(v[0]) == 10 && int(v[1]) == 0 && int(v[2]) < 5500)) ||
  # 2008 SP3 GDR
  (int(v[0]) == 10 && int(v[1]) == 0 && (int(v[2]) >= 5500 && int(v[2]) < 5520)) ||
  # 2008 SP3 QFE
  (int(v[0]) == 10 && int(v[1]) == 0 && (int(v[2]) >= 5750 && int(v[2]) < 5869)) ||
  # 2008 R2 < SP2
  (pcidss && (int(v[0]) == 10 && int(v[1]) == 50 && int(v[2]) < 4000)) ||
  # 2008 R2 SP2 GDR
  (int(v[0]) == 10 && int(v[1]) == 50 && (int(v[2]) >= 4000 && int(v[2]) < 4033)) ||
  # 2008 R2 SP2 QFE
  (int(v[0]) == 10 && int(v[1]) == 50 && (int(v[2]) >= 4251 && int(v[2]) < 4321)) ||
  # 2012 < SP1
  (pcidss && (int(v[0]) == 11 && int(v[1]) == 0 && int(v[2]) < 3000)) ||
  # 2012 GDR
  (int(v[0]) == 11 && int(v[1]) == 0 && (int(v[2]) >= 3000 && int(v[2]) < 3153)) ||
  # 2012 QFE
  (int(v[0]) == 11 && int(v[1]) == 0 && (int(v[2]) >= 3300 && int(v[2]) < 3460)) ||
  # 2014 GDR
  (int(v[0]) == 12 && int(v[1]) == 0 && (int(v[2]) >= 2000 && int(v[2]) < 2254)) ||
  # 2014 QFE
  (int(v[0]) == 12 && int(v[1]) == 0 && (int(v[2]) >= 2300 && int(v[2]) < 2381))
)
{
  set_kb_item(name:"www/0/XSS", value:TRUE);
  security_warning(port);
  exit(0);
}
audit(AUDIT_INST_VER_NOT_VULN, "MSSQL", ver);
