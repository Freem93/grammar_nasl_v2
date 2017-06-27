#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include('compat.inc');

if (description)
{
  script_id(53897);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/07/14 14:23:28 $");

  script_cve_id(
    "CVE-2009-3555",
    "CVE-2011-0785",
    "CVE-2011-0787",
    "CVE-2011-0792",
    "CVE-2011-0793",
    "CVE-2011-0799",
    "CVE-2011-0804",
    "CVE-2011-0805",
    "CVE-2011-0806"
  );
  script_bugtraq_id(
    47429,
    47430,
    47431,
    47432,
    47436,
    47441,
    47443,
    47451
  );
  script_osvdb_id(
    71952,
    71953,
    71954,
    71955,
    71956,
    71957,
    71958,
    71959,
    75692
  );

  script_name(english:"Oracle Database Multiple Vulnerabilities (April 2011 CPU)");
  script_summary(english:"Checks installed patch info");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the April 2011 Critical
Patch Update (CPU) and therefore is potentially affected by security
issues in the following components :

  - Oracle Warehouse Builder (CVE-2011-0792, CVE-2011-0799)

  - Oracle Security Service (CVE-2009-3555)

  - Application Service Level Management (CVE-2011-0787)

  - Network Foundation (CVE-2011-0806)

  - Oracle Help (CVE-2011-0785)

  - UIX (CVE-2011-0805)

  - Database Vault (CVE-2011-0793, CVE-2011-0804)");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?23d98936");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2011 Oracle
Critical Patch Update advisory.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/13");

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
# APR2011
patches = make_nested_array();

# RDBMS 11.1.0.7
patches["11.1.0.7"]["db"]["nix"] = make_array("patch_level", "11.1.0.7.7", "CPU", "11724999, 11724936");
patches["11.1.0.7"]["db"]["win32"] = make_array("patch_level", "11.1.0.7.38", "CPU", "11741169");
patches["11.1.0.7"]["db"]["win64"] = make_array("patch_level", "11.1.0.7.38", "CPU", "11741170");
# RDBMS 11.2.0.2
patches["11.2.0.2"]["db"]["nix"] = make_array("patch_level", "11.2.0.2.2", "CPU", "11724984, 11724916");
patches["11.2.0.2"]["db"]["win32"] = make_array("patch_level", "11.2.0.2.4", "CPU", "11896290");
patches["11.2.0.2"]["db"]["win64"] = make_array("patch_level", "11.2.0.2.4", "CPU", "11896292");
# RDBMS 11.2.0.1
patches["11.2.0.1"]["db"]["nix"] = make_array("patch_level", "11.2.0.1.5", "CPU", "11724991, 11724930");
patches["11.2.0.1"]["db"]["win32"] = make_array("patch_level", "11.2.0.1.11", "CPU", "11883240");
patches["11.2.0.1"]["db"]["win64"] = make_array("patch_level", "11.2.0.1.11", "CPU", "11731176");
# RDBMS 10.1.0.5
patches["10.1.0.5"]["db"]["nix"] = make_array("patch_level", "10.1.0.5.21", "CPU", "11725035");
patches["10.1.0.5"]["db"]["win32"] = make_array("patch_level", "10.1.0.5.41", "CPU", "11731119");
# RDBMS 10.2.0.5
patches["10.2.0.5"]["db"]["nix"] = make_array("patch_level", "10.2.0.5.3", "CPU", "11725006, 11724962");
patches["10.2.0.5"]["db"]["win32"] = make_array("patch_level", "10.2.0.5.8", "CPU", "12328268");
patches["10.2.0.5"]["db"]["win64"] = make_array("patch_level", "10.2.0.5.8", "CPU", "12328269");
# RDBMS 10.2.0.4
patches["10.2.0.4"]["db"]["nix"] = make_array("patch_level", "10.2.0.4.8", "CPU", "11725015, 11724977");
patches["10.2.0.4"]["db"]["win32"] = make_array("patch_level", "10.2.0.4.44", "CPU", "12328501");
patches["10.2.0.4"]["db"]["win64"] = make_array("patch_level", "10.2.0.4.44", "CPU", "12328503");

check_oracle_database(patches:patches, high_risk:TRUE);
