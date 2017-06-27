#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(17698);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/28 21:52:57 $");

  script_cve_id("CVE-2005-2572");
  script_bugtraq_id(62358);
  script_osvdb_id(18898, 18899);

  script_name(english:"MySQL User-Defined Functions Multiple Vulnerabilities");
  script_summary(english:"Checks for MySQL.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is potentially affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"User-defined functions in MySQL can allow a database user to cause
binary libraries on the host to be loaded.  The insert privilege on
the table 'mysql.func' is required for a user to create user-defined
functions.  When running on Windows and possibly other operating
systems, MySQL is potentially affected by the following
vulnerabilities:

  - If an invalid library is requested the Windows
    function 'LoadLibraryEx' will block processing until
    an error dialog box is acknowledged on the server.
    It is not likely that non-Windows systems are affected
    by this particular issue.

  - MySQL requires that user-defined libraries contain
    functions with names fitting the formats: 'XXX_deinit'
    or 'XXX_init'. However, other libraries are known to 
    contain functions fitting these formats and, when called
    upon, can cause application crashes, memory corruption
    and stack pollution.");

  script_set_attribute(attribute:"solution", value:
"There is currently no known fix or patch to address these issues. 
Instead, make sure access to create user-defined functions is
restricted.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Aug/199");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_family(english:"Databases");

  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  script_require_keys("Settings/PCI_DSS");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("mysql_func.inc");

# Only PCI considers this an issue.
if (!get_kb_item("Settings/PCI_DSS")) exit(0, "PCI-DSS compliance checking is not enabled.");

port = get_service(svc:"mysql", default:3306, exit_on_fail:TRUE);

if (mysql_init(port:port) >= 0)
{
  # Try to get variant and version
  variant = mysql_get_variant();
  version = mysql_get_version();
}
else exit(0, "The service on port "+port+" does not look like MySQL.");

# All versions are vulnerable.
if (report_verbosity > 0)
{
  if (!isnull(variant) && !isnull(version))
  {
    report =
      '\n  Variant           : ' + variant +
      '\n  Installed version : ' + version +
      '\n';
  }
  else
  {
    report = 
      '\nNessus was able to determine a MySQL server is listening on' +
      '\nthe remote host but unable to determine its version and / or' +
      '\nvariant.' +
      '\n';
  }
  security_hole(port:port, extra:report);
}
else security_hole(port);
mysql_close();
