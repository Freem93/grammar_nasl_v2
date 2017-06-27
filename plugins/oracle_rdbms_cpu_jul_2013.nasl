#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include("compat.inc");

if (description)
{
  script_id(68934);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/07/14 14:23:28 $");

  script_cve_id(
    "CVE-2013-3751",
    "CVE-2013-3758",
    "CVE-2013-3774",
    "CVE-2013-3760",
    "CVE-2013-3771",
    "CVE-2013-3789",
    "CVE-2013-3790"
  );
  script_bugtraq_id(
    61205,
    61206,
    61207,
    61209,
    61211,
    61215,
    61219
  );
  script_osvdb_id(
    95263,
    95264,
    95265,
    95266,
    95267,
    95268,
    95278
  );

  script_name(english:"Oracle Database Multiple Vulnerabilities (July 2013 CPU)");
  script_summary(english:"Checks installed patch info");

  script_set_attribute(attribute:"synopsis", value:"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote Oracle database server is missing the July 2013 Critical
Patch Update (CPU) and is, therefore, potentially affected by security
issues in the following components :

  - XML Parser

  - Network Layer

  - Oracle Executable

  - Core RDBMS"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-199/");
  # http://www.oracle.com/technetwork/topics/security/cpujuly2013-1899826.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d601a70e");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2013 Oracle Critical
Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include("global_settings.inc");
include("oracle_rdbms_cpu_func.inc");
include("misc_func.inc");

################################################################################
# JUL2013
patches = make_nested_array();

# RDBMS 11.1.0.7
patches["11.1.0.7"]["db"]["nix"] = make_array("patch_level", "11.1.0.7.16", "CPU", "16742110, 16619896");
patches["11.1.0.7"]["db"]["win32"] = make_array("patch_level", "11.1.0.7.53", "CPU", "16803787");
patches["11.1.0.7"]["db"]["win64"] = make_array("patch_level", "11.1.0.7.53", "CPU", "16803788");
# RDBMS 11.2.0.2
patches["11.2.0.2"]["db"]["nix"] = make_array("patch_level", "11.2.0.2.11", "CPU", "16742100, 16619893");
patches["11.2.0.2"]["db"]["win32"] = make_array("patch_level", "11.2.0.2.26", "CPU", "16345851");
patches["11.2.0.2"]["db"]["win64"] = make_array("patch_level", "11.2.0.2.26", "CPU", "16345852");
# RDBMS 11.2.0.3
patches["11.2.0.3"]["db"]["nix"] = make_array("patch_level", "11.2.0.3.7", "CPU", "16742095, 16619892");
patches["11.2.0.3"]["db"]["win32"] = make_array("patch_level", "11.2.0.3.22", "CPU", "16803774");
patches["11.2.0.3"]["db"]["win64"] = make_array("patch_level", "11.2.0.3.22", "CPU", "16803775");
# RDBMS 10.2.0.5
patches["10.2.0.5"]["db"]["nix"] = make_array("patch_level", "10.2.0.5.12", "CPU", "16742123, 16619894");
patches["10.2.0.5"]["db"]["win32"] = make_array("patch_level", "10.2.0.5.22", "CPU", "16803780");
patches["10.2.0.5"]["db"]["win64"] = make_array("patch_level", "10.2.0.5.22", "CPU", "16803782");
# RDBMS 10.2.0.4
patches["10.2.0.4"]["db"]["nix"] = make_array("patch_level", "10.2.0.4.17", "CPU", "16742253, 16619897");

check_oracle_database(patches:patches, high_risk:TRUE);
