#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73756);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/22 20:55:17 $");

  script_name(english:"Microsoft SQL Server Unsupported Version Detection (remote check)");
  script_summary(english:"Checks the SQL Server version.");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of a database server is running on the remote
host.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Microsoft SQL Server on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=SQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4418a57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Microsoft SQL Server that is currently
supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("mssqlserver_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports(1433, "Services/mssql");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"mssql", default:1433, exit_on_fail:TRUE);
version = get_kb_item_or_exit("MSSQL/"+port+"/Version");
supported_version = '';

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# SQL 2014
if (version =~ '^12\\.0+\\.' && ver_compare(ver:version, fix:'12.0.4100', strict:FALSE) == -1) # < SP1
  supported_version = "12.0.4100 (2014 SP1)";

# SQL 2012
else if (version =~ '^11\\.0+\\.' && ver_compare(ver:version, fix:'11.0.5058', strict:FALSE) == -1) # < SP2
  supported_version = "11.0.5058 (2012 SP2) and 11.0.6020 (2012 SP3)";

# SQL 2008 R2
else if (version =~ '^10\\.50\\.' && ver_compare(ver:version, fix:'10.50.6000', strict:FALSE) == -1) # < SP3
  supported_version = "10.50.6000 (2008 R2 SP3)";

# SQL 2008
else if (version =~ '^10\\.0+\\.' && ver_compare(ver:version, fix:'10.0.6000', strict:FALSE) == -1) # < SP4
  supported_version = "10.00.6000 (2008 SP4)";

else if (
  # SQL 2005
  version =~ '^9\\.0+\\.' ||
  # SQL 2000
  version =~ '^8\\.0+\\.' ||
  # SQL Server 7.0
  version =~ '^7\\.0+\\.' ||
  # SQL Server 6.5
  version =~ '^6\\.50\\.' ||
  # SQL Server 6.0
  version =~ '^6\\.00\\.'
) supported_version = 'This version is no longer supported.';

if (supported_version)
{
  register_unsupported_product(product_name:"Microsoft SQL Server", version:version,
                               cpe_base:"microsoft:sql_server");

  report =
    '\n' + 'The following unsupported installation of Microsoft SQL Server was' +
    '\n' + 'detected :\n' +
    '\n' +
    '\n' + '  Installed version : ' + version +
    '\n' + '  Fixed version     : ' + supported_version + '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else exit(0, "The Microsoft SQL Server install listening on port "+port+" is currently supported.");
