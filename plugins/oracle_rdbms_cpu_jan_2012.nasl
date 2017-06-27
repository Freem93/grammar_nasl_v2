
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include("compat.inc");

if (description)
{
  script_id(57589);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/07/14 14:23:28 $");

  script_cve_id("CVE-2012-0072", "CVE-2012-0082");
  script_bugtraq_id(51453, 51458);
  script_osvdb_id(78418, 78419);

  script_name(english:"Oracle Database Multiple Vulnerabilities (January 2012 CPU)");
  script_summary(english:"Checks installed patch info");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the January 2012
Critical Patch Update (CPU) and, therefore, is potentially affected by
security issues in the following components :

  - Core RDBMS

  - Listener");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11da589e");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2012 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/18");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include("global_settings.inc");
include("oracle_rdbms_cpu_func.inc");
include("misc_func.inc");

################################################################################
# JAN2012
patches = make_nested_array();

# RDBMS 11.1.0.7
patches["11.1.0.7"]["db"]["nix"] = make_array("patch_level", "11.1.0.7.10", "CPU", "13343453, 13343461");
patches["11.1.0.7"]["db"]["win32"] = make_array("patch_level", "11.1.0.7.43", "CPU", "13460955");
patches["11.1.0.7"]["db"]["win64"] = make_array("patch_level", "11.1.0.7.43", "CPU", "13460956");
# RDBMS 11.2.0.2
patches["11.2.0.2"]["db"]["nix"] = make_array("patch_level", "11.2.0.2.5", "CPU", "13343244, 13343424");
patches["11.2.0.2"]["db"]["win32"] = make_array("patch_level", "11.2.0.2.15", "CPU", "13413154");
patches["11.2.0.2"]["db"]["win64"] = make_array("patch_level", "11.2.0.2.15", "CPU", "13413155");
# RDBMS 11.2.0.3
patches["11.2.0.3"]["db"]["nix"] = make_array("patch_level", "11.2.0.3.1", "CPU", "13466801, 13343438");
patches["11.2.0.3"]["db"]["win32"] = make_array("patch_level", "11.2.0.3.1", "CPU", "13413167");
patches["11.2.0.3"]["db"]["win64"] = make_array("patch_level", "11.2.0.3.1", "CPU", "13413168");
# RDBMS 10.1.0.5
patches["10.1.0.5"]["db"]["nix"] = make_array("patch_level", "10.1.0.5.24", "CPU", "13343482");
patches["10.1.0.5"]["db"]["win32"] = make_array("patch_level", "10.1.0.5.44", "CPU", "13413002");
# RDBMS 10.2.0.5
patches["10.2.0.5"]["db"]["nix"] = make_array("patch_level", "10.2.0.5.6", "CPU", "13343467, 13343471");
patches["10.2.0.5"]["db"]["win32"] = make_array("patch_level", "10.2.0.5.14", "CPU", "13460967");
patches["10.2.0.5"]["db"]["win64"] = make_array("patch_level", "10.2.0.5.14", "CPU", "13460968");
# RDBMS 10.2.0.4
patches["10.2.0.4"]["db"]["nix"] = make_array("patch_level", "10.2.0.4.11", "CPU", "12879912, 12879929");
patches["10.2.0.4"]["db"]["win32"] = make_array("patch_level", "10.2.0.4.48", "CPU", "13654060");

check_oracle_database(patches:patches);
