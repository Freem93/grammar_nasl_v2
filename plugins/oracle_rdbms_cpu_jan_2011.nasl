#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include('compat.inc');

if (description)
{
  script_id(51573);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/12/07 21:08:18 $");

  script_cve_id(
    "CVE-2010-3590",
    "CVE-2010-3600",
    "CVE-2010-4413",
    "CVE-2010-4420",
    "CVE-2010-4421",
    "CVE-2010-4423"
  );
  script_bugtraq_id(45845,45880,45883,45855,
                    45905,45859);
  script_osvdb_id(70536, 70546, 70548, 70555, 70556, 70557);

  script_name(english:"Oracle Database Multiple Vulnerabilities (January 2011 CPU)");
  script_summary(english:"Checks installed patch info");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the January 2011
Critical Patch Update (CPU) and therefore is potentially affected by
security issues in the following components :

  - Client System Analyzer

  - Cluster Verify Utility

  - Database Vault

  - Oracle Spatial

  - Scheduler Agent

  - UIX");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0fd6b4f5");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2011 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-161");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Oracle Database Client System Analyzer Arbitrary File Upload');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include("global_settings.inc");
include("oracle_rdbms_cpu_func.inc");
include("misc_func.inc");

################################################################################
# JAN2011
patches = make_nested_array();

# RDBMS 11.1.0.7
patches["11.1.0.7"]["db"]["nix"] = make_array("patch_level", "11.1.0.7.6", "CPU", "10249534, 10248531");
patches["11.1.0.7"]["db"]["win32"] = make_array("patch_level", "11.1.0.7.36", "CPU", "10350787");
patches["11.1.0.7"]["db"]["win64"] = make_array("patch_level", "11.1.0.7.36", "CPU", "10350788");
# RDBMS 11.2.0.2
patches["11.2.0.2"]["db"]["nix"] = make_array("patch_level", "11.2.0.2.1", "CPU", "10248523");
patches["11.2.0.2"]["db"]["win32"] = make_array("patch_level", "11.2.0.2.1", "CPU", "10432052");
patches["11.2.0.2"]["db"]["win64"] = make_array("patch_level", "11.2.0.2.1", "CPU", "10432053");
# RDBMS 11.2.0.1
patches["11.2.0.1"]["db"]["nix"] = make_array("patch_level", "11.2.0.1.4", "CPU", "10249532, 10248516");
patches["11.2.0.1"]["db"]["win32"] = make_array("patch_level", "11.2.0.1.10", "CPU", "10432044");
patches["11.2.0.1"]["db"]["win64"] = make_array("patch_level", "11.2.0.1.10", "CPU", "10432045");
# RDBMS 10.2.0.5
patches["10.2.0.5"]["db"]["nix"] = make_array("patch_level", "10.2.0.5.2", "CPU", "10249537, 10248542");
patches["10.2.0.5"]["db"]["win32"] = make_array("patch_level", "10.2.0.5.5", "CPU", "10352672");
patches["10.2.0.5"]["db"]["win64"] = make_array("patch_level", "10.2.0.5.5", "CPU", "10352673");
# RDBMS 10.2.0.4
patches["10.2.0.4"]["db"]["nix"] = make_array("patch_level", "10.2.0.4.7", "CPU", "10249540, 10248636");
patches["10.2.0.4"]["db"]["win32"] = make_array("patch_level", "10.2.0.4.42", "CPU", "10349197");
patches["10.2.0.4"]["db"]["win64"] = make_array("patch_level", "10.2.0.4.42", "CPU", "10349200");

check_oracle_database(patches:patches, high_risk:TRUE);
