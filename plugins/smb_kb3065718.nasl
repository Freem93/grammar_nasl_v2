#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84737);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/12/01 15:02:05 $");

  script_cve_id(
    "CVE-2015-1761",
    "CVE-2015-1762",
    "CVE-2015-1763"
  );
  script_xref(name:"MSFT", value:"MS15-058");

  script_name(english:"MS15-058: Vulnerabilities in SQL Server Could Allow Remote Code Execution (3065718) (uncredentialed check)");
  script_summary(english:"Determines the version of the SQL Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote SQL Server installation is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Microsoft SQL Server installation is affected by multiple
vulnerabilities :

  - A privilege escalation vulnerability exists due to the
    casting of pointers to an incorrect class. An
    authenticated, remote attacker can exploit this, via a
    specially crafted SQL query, to gain elevated
    privileges. (CVE-2015-1761)

  - A remote code execution vulnerability exists due to
    incorrect handling of internal function calls to
    uninitialized memory. An attacker can exploit this, via
    a specially crafted SQL query on an affected SQL server
    that has special permission settings (such as VIEW
    SERVER STATE) turned on, to execute arbitrary code.
    (CVE-2015-1762)

  - A remote code execution vulnerability exists due to
    incorrect handling of internal function calls to
    uninitialized memory. An authenticated, remote attacker
    can exploit this, via a specially crafted SQL query
    designed to execute a virtual function from a wrong
    address, to execute arbitrary code. (CVE-2015-1762)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-058");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SQL Server 2008, 2008 R2,
2012, and 2014.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:microsoft:sql_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

 
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
  # 2008 SP4 GDR
  (int(v[0]) == 10 && int(v[1]) == 0 && (int(v[2]) >= 6000 && int(v[2]) < 6241)) ||
  # 2008 SP4 QFE
  (int(v[0]) == 10 && int(v[1]) == 0 && (int(v[2]) >= 6500 && int(v[2]) < 6535)) ||
  # 2008 SP3 GDR
  (int(v[0]) == 10 && int(v[1]) == 0 && (int(v[2]) >= 5500 && int(v[2]) < 5538)) ||
  # 2008 SP3 QFE
  (int(v[0]) == 10 && int(v[1]) == 0 && (int(v[2]) >= 5750 && int(v[2]) < 5890)) ||

  # 2008 R2 < SP2
  (pcidss && (int(v[0]) == 10 && int(v[1]) == 50 && int(v[2]) < 4000)) ||
  # 2008 R2 SP3 GDR
  (int(v[0]) == 10 && int(v[1]) == 50 && (int(v[2]) >= 6000 && int(v[2]) < 6220)) ||
  # 2008 R2 SP3 QFE
  (int(v[0]) == 10 && int(v[1]) == 50 && (int(v[2]) >= 6500 && int(v[2]) < 6529)) ||
  # 2008 R2 SP2 GDR
  (int(v[0]) == 10 && int(v[1]) == 50 && (int(v[2]) >= 4000 && int(v[2]) < 4042)) ||
  # 2008 R2 SP2 QFE
  (int(v[0]) == 10 && int(v[1]) == 50 && (int(v[2]) >= 4251 && int(v[2]) < 4339)) ||

  # 2012 < SP1
  (pcidss && (int(v[0]) == 11 && int(v[1]) == 0 && int(v[2]) < 3000)) ||
  # 2012 SP2 GDR
  (int(v[0]) == 11 && int(v[1]) == 0 && (int(v[2]) >= 5058 && int(v[2]) < 5343)) ||
  # 2012 SP2 QFE
  (int(v[0]) == 11 && int(v[1]) == 0 && (int(v[2]) >= 5532 && int(v[2]) < 5613)) ||
  # 2012 SP1 GDR
  (int(v[0]) == 11 && int(v[1]) == 0 && (int(v[2]) >= 3000 && int(v[2]) < 3156)) ||
  # 2012 SP1 QFE
  (int(v[0]) == 11 && int(v[1]) == 0 && (int(v[2]) >= 3300 && int(v[2]) < 3513)) ||

  # 2014 GDR
  (int(v[0]) == 12 && int(v[1]) == 0 && (int(v[2]) >= 2000 && int(v[2]) < 2269)) ||
  # 2014 QFE
  (int(v[0]) == 12 && int(v[1]) == 0 && (int(v[2]) >= 2300 && int(v[2]) < 2548))
)
{
  security_hole(port);
  exit(0);
}
audit(AUDIT_INST_VER_NOT_VULN, "MSSQL", ver);
