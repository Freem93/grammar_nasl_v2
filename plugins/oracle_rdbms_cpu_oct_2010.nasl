#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include('compat.inc');

if (description)
{
  script_id(50652);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2015/07/14 14:23:28 $");

  script_cve_id(
    "CVE-2010-1321",
    "CVE-2010-2389",
    "CVE-2010-2390",
    "CVE-2010-2391",
    "CVE-2010-2407",
    "CVE-2010-2411",
    "CVE-2010-2412",
    "CVE-2010-2415",
    "CVE-2010-2419"
  );
  script_bugtraq_id(
    40235,
    43935,
    43940,
    43945,
    43956,
    43958,
    43961,
    43964,
    43970
  );
  script_osvdb_id(
    64744,
    70063,
    70064,
    70077,
    70078,
    70079,
    70080,
    70081,
    70082,
    70083
  );
  script_xref(name:"Secunia", value:"41815");

  script_name(english:"Oracle Database Multiple Vulnerabilities (October 2010 CPU)");
  script_summary(english:"Checks installed patch info");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the October 2010
Critical Patch Update (CPU) and therefore is potentially affected by
security issues in the following components :

  - Enterprise Manager Console

  - Java Virtual Machine

  - Change Data Capture

  - OLAP

  - Job Queue

  - XDK

  - Core RDBMS

  - Perl");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ed3b5c9");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2010 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include("global_settings.inc");
include("oracle_rdbms_cpu_func.inc");
include("misc_func.inc");

################################################################################
# OCT2010
patches = make_nested_array();

# RDBMS 11.1.0.7
patches["11.1.0.7"]["db"]["nix"] = make_array("patch_level", "11.1.0.7.5", "CPU", "9952269, 9952228");
patches["11.1.0.7"]["db"]["win32"] = make_array("patch_level", "11.1.0.7.34", "CPU", "9773817");
patches["11.1.0.7"]["db"]["win64"] = make_array("patch_level", "11.1.0.7.34", "CPU", "9773825");
# RDBMS 11.2.0.1
patches["11.2.0.1"]["db"]["nix"] = make_array("patch_level", "11.2.0.1.3", "CPU", "9952260, 9952216");
patches["11.2.0.1"]["db"]["win32"] = make_array("patch_level", "11.2.0.1.6", "CPU", "10100100");
patches["11.2.0.1"]["db"]["win64"] = make_array("patch_level", "11.2.0.1.6", "CPU", "10100101");
# RDBMS 10.1.0.5
patches["10.1.0.5"]["db"]["nix"] = make_array("patch_level", "10.1.0.5.20", "CPU", "9952279");
patches["10.1.0.5"]["db"]["win32"] = make_array("patch_level", "10.1.0.5.40", "CPU", "10089559");
# RDBMS 10.2.0.5
patches["10.2.0.5"]["db"]["nix"] = make_array("patch_level", "10.2.0.5.1", "CPU", "9952270, 9952230");
patches["10.2.0.5"]["db"]["win32"] = make_array("patch_level", "10.2.0.5.1", "CPU", "10058290");
patches["10.2.0.5"]["db"]["win64"] = make_array("patch_level", "10.2.0.5.1", "CPU", "10099855");
# RDBMS 10.2.0.4
patches["10.2.0.4"]["db"]["nix"] = make_array("patch_level", "10.2.0.4.6", "CPU", "9952272, 9952234");
patches["10.2.0.4"]["db"]["win32"] = make_array("patch_level", "10.2.0.4.40", "CPU", "10084980");
patches["10.2.0.4"]["db"]["win64"] = make_array("patch_level", "10.2.0.4.40", "CPU", "10084982");


check_oracle_database(patches:patches, high_risk:TRUE);
