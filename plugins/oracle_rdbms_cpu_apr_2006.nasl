#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include('compat.inc');

if (description)
{
  script_id(56052);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/07/14 14:23:28 $");

  script_cve_id(
    "CVE-2006-1705",
    "CVE-2006-1866",
    "CVE-2006-1867",
    "CVE-2006-1868",
    "CVE-2006-1869",
    "CVE-2006-1870",
    "CVE-2006-1871",
    "CVE-2006-1872",
    "CVE-2006-1873",
    "CVE-2006-1874",
    "CVE-2006-1875",
    "CVE-2006-1876",
    "CVE-2006-1877"
  );
  script_bugtraq_id(17590);
  script_osvdb_id(
    24505,
    24848,
    24850,
    24851,
    24852,
    24853,
    24854,
    24855,
    24856,
    24857,
    24858,
    24859,
    24860,
    24861
  );

  script_name(english:"Oracle Database Multiple Vulnerabilities (April 2006 CPU)");
  script_summary(english:"Checks installed patch info");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the April 2006 Critical
Patch Update (CPU) and therefore is potentially affected by security
issues in the following components :

  - Advanced Replication

  - Dictionary

  - Export

  - Log Miner

  - ModPL/SQL for Apache

  - Oracle Enterprise Manager Intelligent Agent

  - Oracle Spatial");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ffdc65d");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2006 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/04/18");
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
# APR2006
patches = make_nested_array();

# RDBMS 10.1.0.4
patches["10.1.0.4"]["db"]["nix"] = make_array("patch_level", "10.1.0.4.5", "CPU", "5049067");
patches["10.1.0.4"]["db"]["win32"] = make_array("patch_level", "10.1.0.4.13", "CPU", "5059200");
# RDBMS 10.1.0.5
patches["10.1.0.5"]["db"]["nix"] = make_array("patch_level", "10.1.0.5.2", "CPU", "5049074");
patches["10.1.0.5"]["db"]["win32"] = make_array("patch_level", "10.1.0.5.2", "CPU", "5057606");
# RDBMS 10.2.0.2
patches["10.2.0.2"]["db"]["nix"] = make_array("patch_level", "10.2.0.2.1", "CPU", "5079037");
patches["10.2.0.2"]["db"]["win32"] = make_array("patch_level", "10.2.0.2.1", "CPU", "5140461");
patches["10.2.0.2"]["db"]["win64"] = make_array("patch_level", "10.2.0.2.1", "CPU", "5140567");
# RDBMS 10.2.0.1
patches["10.2.0.1"]["db"]["nix"] = make_array("patch_level", "10.2.0.1.2", "CPU", "5049080");
patches["10.2.0.1"]["db"]["win32"] = make_array("patch_level", "10.2.0.1.6", "CPU", "5059238");
patches["10.2.0.1"]["db"]["win64"] = make_array("patch_level", "10.2.0.1.6", "CPU", "5059261");
# RDBMS 10.1.0.3
patches["10.1.0.3"]["db"]["nix"] = make_array("patch_level", "10.1.0.3.6", "CPU", "5158022");

check_oracle_database(patches:patches, high_risk:TRUE);
