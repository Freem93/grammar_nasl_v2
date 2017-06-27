#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include("compat.inc");

if (description)
{
  script_id(90762);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/07 21:08:18 $");

  script_cve_id(
    "CVE-2016-0677",
    "CVE-2016-0681",
    "CVE-2016-0690",
    "CVE-2016-0691",
    "CVE-2016-3454"
  );
  script_osvdb_id(
    137249,
    137250,
    137251,
    137252,
    137253
  );

  script_name(english:"Oracle Database Multiple Vulnerabilities (April 2016 CPU)");
  script_summary(english:"Checks the installed patch info.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Database Server is missing the April 2016 Critical
Patch Update (CPU). It is, therefore, affected by multiple
vulnerabilities in the following components :

  - An unspecified flaw exists in the RDBMS Security
    component that allows a local attacker to cause a
    denial of service condition. (CVE-2016-0677)

  - An unspecified flaw exists in the  Oracle OLAP component
    that allows a local attacker to gain elevated
    privileges. (CVE-2016-0681)

  - Multiple unspecified flaws exist in the RDBMS Security
    component that allow a local attacker to impact
    integrity. (CVE-2016-0690, CVE-2016-0691)

  - An unspecified flaw exists in the Java VM component that
    allows an unauthenticated, remote attacker to execute
    arbitrary code. (CVE-2016-3454)");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?855180af");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2016 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include("global_settings.inc");
include("oracle_rdbms_cpu_func.inc");
include("misc_func.inc");

################################################################################
# APR2016
patches = make_nested_array();

# RDBMS 12.1.0.2
patches["12.1.0.2"]["db"]["nix"] = make_array("patch_level", "12.1.0.2.160419", "CPU", "22291127, 22806133");
patches["12.1.0.2"]["db"]["win"] = make_array("patch_level", "12.1.0.2.160419", "CPU", "22809813");
# RDBMS 12.1.0.1 #
patches["12.1.0.1"]["db"]["nix"] = make_array("patch_level", "12.1.0.1.160419", "CPU", "22291141");
patches["12.1.0.1"]["db"]["win"] = make_array("patch_level", "12.1.0.1.160419", "CPU", "22617408");
# RDBMS 11.2.0.4 #
patches["11.2.0.4"]["db"]["nix"] = make_array("patch_level", "11.2.0.4.160419", "CPU", "22502493, 22502456");
patches["11.2.0.4"]["db"]["win"] = make_array("patch_level", "11.2.0.4.160419", "CPU", "22839608");

# JVM 12.1.0.2
patches["12.1.0.2"]["ojvm"]["nix"] = make_array("patch_level", "12.1.0.2.160419", "CPU", "22674709");
patches["12.1.0.2"]["ojvm"]["win"] = make_array("patch_level", "12.1.0.2.160419", "CPU", "22839633");
# JVM 12.1.0.1
patches["12.1.0.1"]["ojvm"]["nix"] = make_array("patch_level", "12.1.0.1.160419", "CPU", "22674703");
patches["12.1.0.1"]["ojvm"]["win"] = make_array("patch_level", "12.1.0.1.160419", "CPU", "22839627");
# JVM 11.2.0.4
patches["11.2.0.4"]["ojvm"]["nix"] = make_array("patch_level", "11.2.0.4.160419", "CPU", "22674697");
patches["11.2.0.4"]["ojvm"]["win"] = make_array("patch_level", "11.2.0.4.160419", "CPU", "22839614");

check_oracle_database(patches:patches, high_risk:TRUE);
