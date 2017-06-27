#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64784);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/02/03 17:44:57 $");

  script_name(english:"Microsoft SQL Server Unsupported Version Detection");
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
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("mssql_version.nasl");
  script_require_ports(139, 445);
  script_require_keys("mssql/installed");
  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");

function get_install_text(version, verbose_version, path, sqltype, supported_version)
{
  local_var res;
  if(isnull(version) || isnull(supported_version))
    exit(1, 'Missing argument to get_install_text()');
  res =  '\n  Installed version         : ' + version;
  if (!isnull(verbose_version)) res += ' (' + verbose_version + ')';
  if (!isnull(sqltype)) res += ' ' + sqltype;
  if(!empty_or_null(path))
    res +='\n  Install path              : ' + path;
  res += '\n  Minimum supported version : ' + supported_version + '\n';
  return res;
}

port = get_kb_item("SMB/transport");
if (!port) port = 445;

ver_list = get_kb_list_or_exit("mssql/installs/*/SQLVersion");
info = '';

foreach item (keys(ver_list))
{
  item -= 'mssql/installs/';
  item -= '/SQLVersion';
  path = item;

  version = get_kb_item_or_exit("mssql/installs/" + path + "/SQLVersion");

  verbose_version = get_kb_item("mssql/installs/" + path + "/SQLVerboseVersion");

  sqltype = get_kb_item("mssql/installs/" + path + "/edition_type");
  if (isnull(sqltype)) sqltype = get_kb_item("mssql/installs/" + path + "/edition");

  # Windows Internal Database - Don't report as its covered by OS updates
  if ("Windows Internal Database" >< sqltype)
  {
    continue;
  }

  # SQL 2014
  if (
    version =~ "^12\.0+\." &&
    ver_compare(ver:version, fix:'12.0.4100', strict:FALSE) == -1 # < SP1
  )
  {
    register_unsupported_product(product_name:"Microsoft SQL Server", version:version,
                                 cpe_base:"microsoft:sql_server");
    info += get_install_text(version: version, verbose_version: verbose_version, path:path,
                             sqltype: sqltype, supported_version: "12.0.4100 (2014 SP1)");
  }

  # SQL 2012
  else if (
    version =~ "^11\.0+\." &&
    (sqltype && "Enterprise Core" >!< sqltype) &&
    ver_compare(ver:version, fix:"11.0.5058", strict:FALSE) == -1 # < SP2
  )
  {
    register_unsupported_product(product_name:"Microsoft SQL Server", version:version,
                                 cpe_base:"microsoft:sql_server");
    info += get_install_text(version: version, verbose_version: verbose_version, path:path,
                             sqltype: sqltype, supported_version: "11.0.5058 (2012 SP2) and 11.0.6020 (2012 SP3)");
  }

  # SQL 2008 R2
  else if (
    version =~ "^10\.50\." &&
    (sqltype && "Parallel Data Warehouse" >!< sqltype) &&
    ver_compare(ver:version, fix:"10.50.6000", strict:FALSE) == -1 # < SP3
  )
  {
    register_unsupported_product(product_name:"Microsoft SQL Server", version:version,
                                 cpe_base:"microsoft:sql_server");

    info += get_install_text(version: version, verbose_version: verbose_version, path:path,
                             sqltype: sqltype, supported_version: "10.50.6000 (2008 R2 SP3)");
  }

  # SQL 2008
  else if (
    version =~ "^10\.0+\." &&
    ver_compare(ver:version, fix:"10.00.6000", strict:FALSE) == -1 # < SP4
  )
  {
    register_unsupported_product(product_name:"Microsoft SQL Server", version:version,
                                 cpe_base:"microsoft:sql_server");

    info += get_install_text(version: version, verbose_version: verbose_version, path:path,
                             sqltype: sqltype, supported_version: "10.00.6000 (2008 SP4)");
  }

  # Completely unsupported SQL Servers versions
  else if (
    # SQL 2005
    version =~ "^9\.00\." ||
    # SQL 2000
    version =~ "^8\.00\." ||
    # SQL Server 7.0
    version =~ "^7\.00\." ||
    # SQL Server 6.5
    version =~ "^6\.50\." ||
    # SQL Server 6.0
    version =~ "^6\.00\."
  )
  {
    register_unsupported_product(product_name:"Microsoft SQL Server", version:version,
                                 cpe_base:"microsoft:sql_server");

    info += get_install_text(version: version, verbose_version: verbose_version, path:path,
                             sqltype: sqltype, supported_version: "This version is no longer supported.");
  }
}

if (info != '')
{
  report = '\n' + 'The following unsupported installations of Microsoft SQL Server were' +
           '\n' + 'detected :\n' +
           info;
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_NOT_INST, "An unsupported version of Microsoft SQL Server");
