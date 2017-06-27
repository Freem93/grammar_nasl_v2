#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72909);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/06 17:11:37 $");

  script_cve_id("CVE-2011-1280");
  script_bugtraq_id(48196);
  script_osvdb_id(72934);
  script_xref(name:"MSFT", value:"MS11-049");
  script_xref(name:"IAVB", value:"2011-B-0064");

  script_name(english:"MS11-049: Vulnerability in the Microsoft XML Editor Could Allow Information Disclosure (2543893) (uncredentialed check)");
  script_summary(english:"Checks version of SQL Server");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An application on the remote Windows host has an information disclosure
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An application on the remote host has an information disclosure
vulnerability.  When parsing a specially crafted Web Service Discovery
(.disco) file, external XML entities are allowed for untrusted user
input.  A remote attacker could exploit this by tricking a user into
opening a specially crafted .disco file, resulting in the disclosure of
sensitive information."
  );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-049");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for SQL Server 2005, 2008 and
2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("mssqlserver_detect.nasl");
  script_require_ports(1433, "Services/mssql");
  script_require_keys("Settings/ParanoidReport");

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
  # 2005 < SP3
  (pcidss && (v[0] == 9 && v[1] == 0 && v[2] < 4035)) ||
  # 2005 SP3 GDR
  (v[0] == 9 && v[1] == 0 && (v[2] >= 4035 && v[2] < 4060)) ||
  # 2005 SP3 QFE
  (v[0] == 9 && v[1] == 0 && (v[2] >= 4300 && v[2] < 4340)) ||
  # 2005 SP4 GDR
  (v[0] == 9 && v[1] == 0 && (v[2] >= 5000 && v[2] < 5057)) ||
  # 2005 SP4 QFE
  (v[0] == 9 && v[1] == 0 && (v[2] >= 5200 && v[2] < 5292)) ||
  # 2008 < SP1
  (pcidss && (v[0] == 10 && v[1] == 0 && v[2] < 2531)) ||
  # 2008 SP1
  (v[0] == 10 && v[1] == 0 && (v[2] >= 2531 && v[2] < 2573)) ||
  # 2008 SP2
  (v[0] == 10 && v[1] == 0 && (v[2] >= 4000 && v[2] < 4064)) ||
  # 2008 R2 GDR
  (v[0] == 10 && v[1] == 50 && (v[2] >= 1600 && int(v[2]) < 1617)) ||
  # 2008 R2 QFE
  (v[0] == 10 && v[1] == 50 && (v[2] >= 1700 && int(v[2]) < 1790))
)
{
  security_warning(port);
  exit(0);
}
audit(AUDIT_INST_VER_NOT_VULN, "MSSQL", ver);
