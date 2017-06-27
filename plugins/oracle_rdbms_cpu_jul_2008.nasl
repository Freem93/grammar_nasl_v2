#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include('compat.inc');

if (description)
{
  script_id(56061);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/07/14 14:23:28 $");

  script_cve_id(
    "CVE-2008-2587",
    "CVE-2008-2590",
    "CVE-2008-2591",
    "CVE-2008-2592",
    "CVE-2008-2600",
    "CVE-2008-2602",
    "CVE-2008-2603",
    "CVE-2008-2604",
    "CVE-2008-2605",
    "CVE-2008-2607",
    "CVE-2008-2608",
    "CVE-2008-2611",
    "CVE-2008-2613"
  );
  script_bugtraq_id(30177);
  script_osvdb_id(
    47708,
    47709,
    47727,
    47728,
    47729,
    47730,
    47731,
    47732,
    47733,
    47734,
    47735,
    47736,
    47737
  );

  script_name(english:"Oracle Database Multiple Vulnerabilities (July 2008 CPU)");
  script_summary(english:"Checks installed patch info");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the July 2008 Critical
Patch Update (CPU) and therefore is potentially affected by security
issues in the following components :

  - Advanced Queuing

  - Advanced Replication

  - Authentication

  - Core RDBMS

  - Data Pump

  - Database Scheduler

  - Instance Management

  - Oracle Spatial

  - Oracle Database Vault

  - Resource Manager");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a924a15");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2008 Oracle Critical
Patch Update advisory.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include("global_settings.inc");
include("oracle_rdbms_cpu_func.inc");
include("misc_func.inc");

################################################################################
# JUL2008
patches = make_nested_array();

# RDBMS 11.1.0.6
patches["11.1.0.6"]["db"]["nix"] = make_array("patch_level", "11.1.0.6.3", "CPU", "7150417");
patches["11.1.0.6"]["db"]["win32"] = make_array("patch_level", "11.1.0.6.6", "CPU", "7210195");
patches["11.1.0.6"]["db"]["win64"] = make_array("patch_level", "11.1.0.6.6", "CPU", "7210197");
# RDBMS 10.1.0.5
patches["10.1.0.5"]["db"]["nix"] = make_array("patch_level", "10.1.0.5.11", "CPU", "7154097");
patches["10.1.0.5"]["db"]["win32"] = make_array("patch_level", "10.1.0.5.26", "CPU", "7047034");
# RDBMS 10.2.0.4
patches["10.2.0.4"]["db"]["nix"] = make_array("patch_level", "10.2.0.4.0.1", "CPU", "7150470");
patches["10.2.0.4"]["db"]["win32"] = make_array("patch_level", "10.2.0.4.5", "CPU", "7218676");
patches["10.2.0.4"]["db"]["win64"] = make_array("patch_level", "10.2.0.4.5", "CPU", "7218677");
# RDBMS 10.2.0.3
patches["10.2.0.3"]["db"]["nix"] = make_array("patch_level", "10.2.0.3.7", "CPU", "7150622");
patches["10.2.0.3"]["db"]["win32"] = make_array("patch_level", "10.2.0.3.25", "CPU", "7252496");
patches["10.2.0.3"]["db"]["win64"] = make_array("patch_level", "10.2.0.3.25", "CPU", "7252498");
# RDBMS 10.2.0.2
patches["10.2.0.2"]["db"]["nix"] = make_array("patch_level", "10.2.0.2.10", "CPU", "7154083");

check_oracle_database(patches:patches);
