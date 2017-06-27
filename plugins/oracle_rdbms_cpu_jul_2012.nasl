#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include("compat.inc");

if (description)
{
  script_id(60048);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/07/14 14:23:28 $");

  script_cve_id(
    "CVE-2012-1737",
    "CVE-2012-1745",
    "CVE-2012-1746",
    "CVE-2012-1747",
    "CVE-2012-3132",
    "CVE-2012-3134"
  );
  script_bugtraq_id(54496, 54501, 54507, 54518, 54569, 54884);
  script_osvdb_id(83945, 83946, 83947, 83948, 83949, 84564);

  script_name(english:"Oracle Database Multiple Vulnerabilities (July 2012 CPU)");
  script_summary(english:"Checks installed patch info");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the July 2012 Critical
Patch Update (CPU) and is, therefore, potentially affected by security
issues in the following components :

  - Enterprise Manager

  - Network Layer

  - Core RDBMS");

   # http://www.oracle.com/technetwork/topics/security/cpujul2012-392727.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd39edea");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2012 Oracle Critical
Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/19");

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
# JUL2012
patches = make_nested_array();

# RDBMS 11.1.0.7
patches["11.1.0.7"]["db"]["nix"] = make_array("patch_level", "11.1.0.7.12", "CPU", "14038803, 13923474");
patches["11.1.0.7"]["db"]["win32"] = make_array("patch_level", "11.1.0.7.47", "CPU", "14109867");
patches["11.1.0.7"]["db"]["win64"] = make_array("patch_level", "11.1.0.7.47", "CPU", "14109868");
# RDBMS 11.2.0.2
patches["11.2.0.2"]["db"]["nix"] = make_array("patch_level", "11.2.0.2.7", "CPU", "14038791, 13923804");
patches["11.2.0.2"]["db"]["win32"] = make_array("patch_level", "11.2.0.2.20", "CPU", "14134042");
patches["11.2.0.2"]["db"]["win64"] = make_array("patch_level", "11.2.0.2.20", "CPU", "14134043");
# RDBMS 11.2.0.3
patches["11.2.0.3"]["db"]["nix"] = make_array("patch_level", "11.2.0.3.3", "CPU", "14038787, 13923374");
patches["11.2.0.3"]["db"]["win32"] = make_array("patch_level", "11.2.0.3.7", "CPU", "14223717");
patches["11.2.0.3"]["db"]["win64"] = make_array("patch_level", "11.2.0.3.7", "CPU", "14223718");
# RDBMS 10.2.0.5
patches["10.2.0.5"]["db"]["nix"] = make_array("patch_level", "10.2.0.5.8", "CPU", "14038805, 13923855");
patches["10.2.0.5"]["db"]["win32"] = make_array("patch_level", "10.2.0.5.17", "CPU", "14134051");
patches["10.2.0.5"]["db"]["win64"] = make_array("patch_level", "10.2.0.5.17", "CPU", "14134053");
# RDBMS 10.2.0.4
patches["10.2.0.4"]["db"]["nix"] = make_array("patch_level", "10.2.0.4.13", "CPU", "14038814, 13923851");

check_oracle_database(patches:patches);
