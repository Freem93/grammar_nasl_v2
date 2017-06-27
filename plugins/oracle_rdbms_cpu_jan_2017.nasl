#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include("compat.inc");

if (description)
{
  script_id(96611);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/04/21 16:53:28 $");

  script_cve_id("CVE-2017-3310", "CVE-2017-3240");
  script_bugtraq_id(95477, 95481);
  script_osvdb_id(150441, 150442);

  script_name(english:"Oracle Database Multiple Vulnerabilities (January 2017 CPU)");
  script_summary(english:"Checks the installed patch info.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Database Server is missing the January 2017 Critical
Patch Update (CPU). It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified flaw exists in the OJVM component that
    allows an authenticated, remote attacker to execute
    arbitrary code. (CVE-2017-3310)

  - An unspecified flaw exists in the RDBMS Security
    component that allows a local attacker to disclose
    potentially sensitive information. (CVE-2017-3240)");
  # http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89a8e429");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2017 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include("global_settings.inc");
include("oracle_rdbms_cpu_func.inc");
include("misc_func.inc");

################################################################################
# JAN2017
patches = make_nested_array();

# RDBMS 12.1.0.2
patches["12.1.0.2"]["db"]["nix"] = make_array("patch_level", "12.1.0.2.170117", "CPU", "24732082");
patches["12.1.0.2"]["db"]["win"] = make_array("patch_level", "12.1.0.2.170117", "CPU", "25115951");

# JVM 12.1.0.2
patches["12.1.0.2"]["ojvm"]["nix"] = make_array("patch_level", "12.1.0.2.170117", "CPU", "24917972");
patches["12.1.0.2"]["ojvm"]["win"] = make_array("patch_level", "12.1.0.2.170117", "CPU", "25112498");
# JVM 11.2.0.4
patches["11.2.0.4"]["ojvm"]["nix"] = make_array("patch_level", "11.2.0.4.170117", "CPU", "24917954");
patches["11.2.0.4"]["ojvm"]["win"] = make_array("patch_level", "11.2.0.4.170117", "CPU", "25043019");

check_oracle_database(patches:patches, high_risk:TRUE);
