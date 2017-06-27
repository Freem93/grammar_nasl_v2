#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include("compat.inc");

if (description)
{
  script_id(84822);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/12/10 21:48:40 $");

  script_cve_id(
    "CVE-2015-0468",
    "CVE-2015-2585",
    "CVE-2015-2586",
    "CVE-2015-2595",
    "CVE-2015-2599",
    "CVE-2015-2629",
    "CVE-2015-2655",
    "CVE-2015-4740",
    "CVE-2015-4753",
    "CVE-2015-4755"
  );
  script_bugtraq_id(
    75838,
    75839,
    75845,
    75851,
    75852,
    75853,
    75864,
    75865,
    75879,
    75882
  );
  script_osvdb_id(
    124607,
    124608,
    124609,
    124610,
    124611,
    124612,
    124613,
    124614,
    124615,
    124616
  );

  script_name(english:"Oracle Database Multiple Vulnerabilities (July 2015 CPU)");
  script_summary(english:"Checks the installed patch info.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the July 2015 Critical
Patch Update (CPU). It is, therefore, affected by multiple
vulnerabilities in the following components :

  - Application Express (CVE-2015-2655, CVE-2015-2585,
    CVE-2015-2586)
  - Core RDBMS (CVE-2015-0468)
  - Java VM (CVE-2015-2629)
  - Oracle OLAP (CVE-2015-2595)
  - RDBMS Partitioning (CVE-2015-4740)
  - RDBMS Scheduler (CVE-2015-2599)
  - RDBMS Security (CVE-2015-4755)
  - RDBMS Support Tools (CVE-2015-4753)");
  # http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d18c2a85");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2015 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include("global_settings.inc");
include("oracle_rdbms_cpu_func.inc");
include("misc_func.inc");

################################################################################
# July 2015
patches = make_nested_array();

# RDBMS 12.1.0.2
patches["12.1.0.2"]["db"]["nix"] = make_array("patch_level", "12.1.0.2.4", "CPU", "20831110");
patches["12.1.0.2"]["db"]["win"] = make_array("patch_level", "12.1.0.2.7", "CPU", "21126814");
# RDBMS 12.1.0.1
patches["12.1.0.1"]["db"]["nix"] = make_array("patch_level", "12.1.0.1.8", "CPU", "20831107");
patches["12.1.0.1"]["db"]["win"] = make_array("patch_level", "12.1.0.1.20", "CPU", "21076681");
# RDBMS 11.2.0.4
patches["11.2.0.4"]["db"]["nix"] = make_array("patch_level", "11.2.0.4.7", "CPU", "20803583, 20760982");
patches["11.2.0.4"]["db"]["win"] = make_array("patch_level", "11.2.0.4.19", "CPU", "21691487");
# RDBMS 11.2.0.3
patches["11.2.0.3"]["db"]["nix"] = make_array("patch_level", "11.2.0.3.15", "CPU", "20803576, 20760997");
patches["11.2.0.3"]["db"]["win32"] = make_array("patch_level", "11.2.0.3.39", "CPU", "21104035");
patches["11.2.0.3"]["db"]["win64"] = make_array("patch_level", "11.2.0.3.39", "CPU", "21104036");
# RDBMS 11.1.0.7
patches["11.1.0.7"]["db"]["nix"] = make_array("patch_level", "11.1.0.7.24", "CPU", "20803573, 20761024");
patches["11.1.0.7"]["db"]["win32"] = make_array("patch_level", "11.1.0.7.61", "CPU", "21104029");
patches["11.1.0.7"]["db"]["win64"] = make_array("patch_level", "11.1.0.7.61", "CPU", "21104030");

# JVM 12.1.0.2
patches["12.1.0.2"]["ojvm"]["nix"] = make_array("patch_level", "12.1.0.2.4", "CPU", "21068507");
patches["12.1.0.2"]["ojvm"]["win"] = make_array("patch_level", "12.1.0.2.3", "CPU", "21153530");
# JVM 12.1.0.1
patches["12.1.0.1"]["ojvm"]["nix"] = make_array("patch_level", "12.1.0.1.4", "CPU", "21068523");
patches["12.1.0.1"]["ojvm"]["win"] = make_array("patch_level", "12.1.0.1.4", "CPU", "21153513");
# JVM 11.2.0.4
patches["11.2.0.4"]["ojvm"]["nix"] = make_array("patch_level", "11.2.0.4.4", "CPU", "21068539");
patches["11.2.0.4"]["ojvm"]["win"] = make_array("patch_level", "11.2.0.4.4", "CPU", "21153498");
# JVM 11.2.0.3
patches["11.2.0.3"]["ojvm"]["nix"] = make_array("patch_level", "11.2.0.3.4", "CPU", "21068553");
patches["11.2.0.3"]["ojvm"]["win"] = make_array("patch_level", "11.2.0.3.4", "CPU", "21153470");
# JVM 11.1.0.7
patches["11.1.0.7"]["ojvm"]["nix"] = make_array("patch_level", "11.1.0.7.4", "CPU", "21068565");
patches["11.1.0.7"]["ojvm"]["win"] = make_array("patch_level", "11.1.0.7.4", "CPU", "21153423");

check_oracle_database(patches:patches, high_risk:TRUE);
