#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include("compat.inc");

if (description)
{
  script_id(58798);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/07/14 14:23:28 $");

  script_cve_id(
    "CVE-2012-0510",
    "CVE-2012-0511",
    "CVE-2012-0512",
    "CVE-2012-0519",
    "CVE-2012-0520",
    "CVE-2012-0525",
    "CVE-2012-0526",
    "CVE-2012-0527",
    "CVE-2012-0528",
    "CVE-2012-0534",
    "CVE-2012-0552",
    "CVE-2012-1708"
  );
  script_bugtraq_id(
    53063,
    53072,
    53076,
    53081,
    53084,
    53089,
    53090,
    53092,
    53093,
    53097,
    53101,
    53104
  );
  script_osvdb_id(
    81267,
    81268,
    81270,
    81271,
    81272,
    81273,
    81274,
    81390,
    81391,
    81392,
    81393,
    81394
  );

  script_name(english:"Oracle Database Multiple Vulnerabilities (April 2012 CPU)");
  script_summary(english:"Checks installed patch info");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the April 2012 Critical
Patch Update (CPU) and is, therefore, potentially affected by security
issues in the following components :

  - Core RDBMS

  - Oracle Spatial

  - OCI

  - Enterprise Manager Base Platform

  - Application Express");

  # https://www.teamshatter.com/topics/general/team-shatter-exclusive/advisory-sql-injection-in-oracle-enterprise-manager-searchpage-web-page/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9e3b595");
  # https://www.teamshatter.com/topics/general/team-shatter-exclusive/advisory-http-response-splitting-in-oem-prevpage/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a38b382b");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2012-366314.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9865fa8a");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2012 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/19");

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
# APR2012
patches = make_nested_array();

# RDBMS 11.1.0.7
patches["11.1.0.7"]["db"]["nix"] = make_array("patch_level", "11.1.0.7.11", "CPU", "13632731, 13621679");
patches["11.1.0.7"]["db"]["win32"] = make_array("patch_level", "11.1.0.7.45", "CPU", "13715809");
patches["11.1.0.7"]["db"]["win64"] = make_array("patch_level", "11.1.0.7.45", "CPU", "13715810");
# RDBMS 11.2.0.2
patches["11.2.0.2"]["db"]["nix"] = make_array("patch_level", "11.2.0.2.6", "CPU", "13632725, 13696224");
patches["11.2.0.2"]["db"]["win32"] = make_array("patch_level", "11.2.0.2.17", "CPU", "13697073");
patches["11.2.0.2"]["db"]["win64"] = make_array("patch_level", "11.2.0.2.17", "CPU", "13697074");
# RDBMS 11.2.0.3
patches["11.2.0.3"]["db"]["nix"] = make_array("patch_level", "11.2.0.3.2", "CPU", "13632717, 13696216");
patches["11.2.0.3"]["db"]["win32"] = make_array("patch_level", "11.2.0.3.5", "CPU", "13885388");
patches["11.2.0.3"]["db"]["win64"] = make_array("patch_level", "11.2.0.3.5", "CPU", "13885389");
# RDBMS 10.2.0.5
patches["10.2.0.5"]["db"]["nix"] = make_array("patch_level", "10.2.0.5.7", "CPU", "13632738, 13632743");
patches["10.2.0.5"]["db"]["win32"] = make_array("patch_level", "10.2.0.5.15", "CPU", "13654814");
patches["10.2.0.5"]["db"]["win64"] = make_array("patch_level", "10.2.0.5.15", "CPU", "13654815");
# RDBMS 10.2.0.4
patches["10.2.0.4"]["db"]["nix"] = make_array("patch_level", "10.2.0.4.12", "CPU", "12879926, 12879933");
patches["10.2.0.4"]["db"]["win32"] = make_array("patch_level", "10.2.0.4.49", "CPU", "13928775");
patches["10.2.0.4"]["db"]["win64"] = make_array("patch_level", "10.2.0.4.49", "CPU", "13928776");

check_oracle_database(patches:patches, high_risk:TRUE);
