#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72908);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/09 20:54:59 $");

  script_cve_id(
    "CVE-2009-2500",
    "CVE-2009-2501",
    "CVE-2009-2502",
    "CVE-2009-2503",
    "CVE-2009-2504",
    "CVE-2009-2518",
    "CVE-2009-2528",
    "CVE-2009-3126"
  );
  script_bugtraq_id(
    36619,
    36645,
    36646,
    36647,
    36648,
    36649,
    36650,
    36651
  );
  script_osvdb_id(
    58863,
    58864,
    58865,
    58866,
    58867,
    58868,
    58869,
    58870
  );
  script_xref(name:"MSFT", value:"MS09-062");
  script_xref(name:"IAVA", value:"2009-A-0099");

  script_name(english:"MS09-062: Vulnerabilities in GDI+ Could Allow Remote Code Execution (957488) (uncredentialed check)");
  script_summary(english:"Checks the version of gdiplus.exe");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the Microsoft
GDI rendering engine.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of SQL Server that may host the
RSClientPrint ActiveX control that includes a copy of gdiplus.dll that
is affected by multiple buffer overflow vulnerabilities when viewing
TIFF, PNG, BMP, and Office files that could allow an attacker to execute
arbitrary code on the remote host.  Additionally, there is a GDI+ .NET
API vulnerability that allows a malicious .NET application to gain
unmanaged code execution privileges. 

To exploit these flaws, an attacker would need to send a malformed image
file to a user on the remote host and wait for them to open it using an
affected Microsoft application.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/MS09-062");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SQL Server 2000 and
2005.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(94, 119, 189);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("mssqlserver_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports(1433, "Services/mssql");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"mssql", exit_on_fail:TRUE);

ver = get_kb_item("MSSQL/" + port + "/Version");
if (!ver) audit(AUDIT_SERVICE_VER_FAIL,"MSSQL", port);

v = split(ver, sep:".", keep:FALSE);
for (i=0; i < max_index(v); i++)
  v[i] = int(v[i]);

if (report_paranoia < 2) audit(AUDIT_PARANOID);
pcidss = get_kb_item("Settings/PCI_DSS");

if (
  # 2000 < SP2
  (pcidss && (v[0] == 8 && v[1] == 0 && v[2] < 534)) ||
  # 2000 SP2
  (v[0] == 8 && v[1] == 0 && (v[2] >= 1038 && v[2] < 1067)) ||
  # 2005 < SP2
  (pcidss && (v[0] == 9 && v[1] == 0 && v[2] < 3042)) ||
  # 2005 SP2 GDR
  (v[0] == 9 && v[1] == 0 && (v[2] >= 3000 && v[2] < 3080)) ||
  # 2005 SP2 QFE
  (v[0] == 9 && v[1] == 0 && (v[2] >= 3200 && v[2] < 3353)) ||
  # 2005 SP3 GDR
  (v[0] == 9 && v[1] == 0 && v[2] >= 4035 && v[2] < 4053) ||
  # 2005 SP3 QFE
  (v[0] == 9 && v[1] == 0 && v[2] >= 4200 && v[2] < 4262)
)
{
  security_hole(port);
  exit(0);
}
audit(AUDIT_INST_VER_NOT_VULN, "MSSQL", ver);
