#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include('compat.inc');

if (description)
{
  script_id(56053);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/07/14 14:23:28 $");

  script_cve_id(
    "CVE-2006-3698",
    "CVE-2006-3699",
    "CVE-2006-3700",
    "CVE-2006-3701",
    "CVE-2006-3702",
    "CVE-2006-3703",
    "CVE-2006-3704",
    "CVE-2006-3705"
  );
  script_bugtraq_id(19054);
  script_osvdb_id(
    28887,
    28888,
    28889,
    28890,
    28892,
    28893,
    28894,
    28895,
    28896,
    28897,
    28898,
    28899,
    28900,
    28901,
    28902,
    28903,
    28904,
    28905,
    28906,
    28907,
    28908,
    28909,
    28910,
    28911,
    28912,
    28913,
    28914
  );

  script_name(english:"Oracle Database Multiple Vulnerabilities (July 2006 CPU)");
  script_summary(english:"Checks installed patch info");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the July 2006 Critical
Patch Update (CPU) and therefore is potentially affected by security
issues in the following components :

  - Change Data Capture (CDC)

  - Core RDBMS

  - Data Pump Metadata API

  - Dictionary

  - Export

  - InterMedia

  - OCI

  - Oracle ODBC Driver

  - Query Rewrite/Summary Management

  - RPC

  - Semantic Analysis

  - Statistics

  - Upgrade/Downgrade

  - Web Distributed Authoring and Versionin (DAV)

  - XMLDB");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4088465");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2006 Oracle Critical
Patch Update advisory.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/16");

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
# JUL2006
patches = make_nested_array();

# RDBMS 10.1.0.4
patches["10.1.0.4"]["db"]["nix"] = make_array("patch_level", "10.1.0.4.6", "CPU", "5225796");
patches["10.1.0.4"]["db"]["win32"] = make_array("patch_level", "10.1.0.4.14", "CPU", "5239736");
# RDBMS 10.1.0.5
patches["10.1.0.5"]["db"]["nix"] = make_array("patch_level", "10.1.0.5.3", "CPU", "5225797");
patches["10.1.0.5"]["db"]["win32"] = make_array("patch_level", "10.1.0.5.5", "CPU", "5251148");
# RDBMS 10.2.0.2
patches["10.2.0.2"]["db"]["nix"] = make_array("patch_level", "10.2.0.2.2", "CPU", "5225799");
patches["10.2.0.2"]["db"]["win32"] = make_array("patch_level", "10.2.0.2.4", "CPU", "5251025");
patches["10.2.0.2"]["db"]["win64"] = make_array("patch_level", "10.2.0.2.4", "CPU", "5251028");
# RDBMS 10.2.0.1
patches["10.2.0.1"]["db"]["nix"] = make_array("patch_level", "10.2.0.1.3", "CPU", "5225798");
patches["10.2.0.1"]["db"]["win32"] = make_array("patch_level", "10.2.0.1.7", "CPU", "5239698");
patches["10.2.0.1"]["db"]["win64"] = make_array("patch_level", "10.2.0.1.7", "CPU", "5239701");
# RDBMS 10.1.0.3
patches["10.1.0.3"]["db"]["nix"] = make_array("patch_level", "10.1.0.3.7", "CPU", "5435164");

check_oracle_database(patches:patches, high_risk:TRUE);
