#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78540);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/11/18 21:03:58 $");

  script_cve_id(
    "CVE-2014-0050",
    "CVE-2014-2478",
    "CVE-2014-4289",
    "CVE-2014-4290",
    "CVE-2014-4291",
    "CVE-2014-4292",
    "CVE-2014-4293",
    "CVE-2014-4294",
    "CVE-2014-4295",
    "CVE-2014-4296",
    "CVE-2014-4297",
    "CVE-2014-4298",
    "CVE-2014-4299",
    "CVE-2014-4300",
    "CVE-2014-4301",
    "CVE-2014-4310",
    "CVE-2014-6452",
    "CVE-2014-6453",
    "CVE-2014-6454",
    "CVE-2014-6455",
    "CVE-2014-6467",
    "CVE-2014-6477",
    "CVE-2014-6483",
    "CVE-2014-6537",
    "CVE-2014-6538",
    "CVE-2014-6542",
    "CVE-2014-6543",
    "CVE-2014-6544",
    "CVE-2014-6545",
    "CVE-2014-6546",
    "CVE-2014-6547",
    "CVE-2014-6560",
    "CVE-2014-6563"
  );
  script_bugtraq_id(
    70453,
    70465,
    70467,
    70473,
    70474,
    70480,
    70482,
    70490,
    70492,
    70495,
    70498,
    70499,
    70500,
    70501,
    70502,
    70504,
    70505,
    70508,
    70514,
    70515,
    70524,
    70526,
    70527,
    70528,
    70529,
    70536,
    70541,
    70547,
    70553
  );
  script_osvdb_id(
    102945,
    108046,
    113222,
    113223,
    113224,
    113225,
    113226,
    113227,
    113228,
    113229,
    113230,
    113231,
    113232,
    113233,
    113234,
    113235,
    113236,
    113237,
    113238,
    113239,
    113240,
    113241,
    113242,
    113243,
    113244,
    113245,
    113246,
    113247,
    113248,
    113249,
    113250,
    113291
  );

  script_name(english:"Oracle Database Multiple Vulnerabilities (October 2014 CPU)");
  script_summary(english:"Checks the installed patch info.");

  script_set_attribute(attribute:"synopsis", value:"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the October 2014 Critical
Patch Update (CPU). It is, therefore, affected by security issues in
the following components :

  - Application Express
  - Core RDBMS
  - Java VM
  - JDBC
  - JPublisher
  - SQLJ");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2014-1972960.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6dcc7b47");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2014 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include("global_settings.inc");
include("oracle_rdbms_cpu_func.inc");
include("misc_func.inc");

################################################################################
# OCT2014
patches = make_nested_array();

# RDBMS 11.1.0.7
patches["11.1.0.7"]["db"]["nix"] = make_array("patch_level", "11.1.0.7.21", "CPU", "19274522, 19152553");
patches["11.1.0.7"]["db"]["win32"] = make_array("patch_level", "11.1.0.7.58", "CPU", "19609032");
patches["11.1.0.7"]["db"]["win64"] = make_array("patch_level", "11.1.0.7.58", "CPU", "19609034");
# RDBMS 12.1.0.2
patches["12.1.0.2"]["db"]["nix"] = make_array("patch_level", "12.1.0.2.1", "CPU", "19303936");
# RDBMS 12.1.0.1
patches["12.1.0.1"]["db"]["nix"] = make_array("patch_level", "12.1.0.1.5", "CPU", "19121550");
patches["12.1.0.1"]["db"]["win"] = make_array("patch_level", "12.1.0.1.14", "CPU", "19542943");
# RDBMS 11.2.0.3
patches["11.2.0.3"]["db"]["nix"] = make_array("patch_level", "11.2.0.3.12", "CPU", "19271438, 19121548");
patches["11.2.0.3"]["db"]["win32"] = make_array("patch_level", "11.2.0.3.34", "CPU", "19618574");
patches["11.2.0.3"]["db"]["win64"] = make_array("patch_level", "11.2.0.3.34", "CPU", "19618575");
# RDBMS 11.2.0.4
patches["11.2.0.4"]["db"]["nix"] = make_array("patch_level", "11.2.0.4.4", "CPU", "19271443, 19121551");
patches["11.2.0.4"]["db"]["win"] = make_array("patch_level", "11.2.0.4.10", "CPU", "19651773");
# JVM 11.2.0.3
patches["11.2.0.3"]["ojvm"]["nix"] = make_array("patch_level", "11.2.0.3.1", "CPU", "19282015");
patches["11.2.0.3"]["ojvm"]["win"] = make_array("patch_level", "11.2.0.3.1", "CPU", "19806120");
# JVM 12.1.0.2
patches["12.1.0.2"]["ojvm"]["nix"] = make_array("patch_level", "12.1.0.2.1", "CPU", "19282028");
# JVM 11.1.0.7
patches["11.1.0.7"]["ojvm"]["nix"] = make_array("patch_level", "11.1.0.7.1", "CPU", "19282002");
patches["11.1.0.7"]["ojvm"]["win"] = make_array("patch_level", "11.1.0.7.1", "CPU", "19806118");
# JVM 11.2.0.4
patches["11.2.0.4"]["ojvm"]["nix"] = make_array("patch_level", "11.2.0.4.1", "CPU", "19282021");
patches["11.2.0.4"]["ojvm"]["win"] = make_array("patch_level", "11.2.0.4.1", "CPU", "19799291");
# JVM 12.1.0.1
patches["12.1.0.1"]["ojvm"]["nix"] = make_array("patch_level", "12.1.0.1.1", "CPU", "19282024");
patches["12.1.0.1"]["ojvm"]["win"] = make_array("patch_level", "12.1.0.1.1", "CPU", "19801531");

check_oracle_database(patches:patches, high_risk:TRUE);
