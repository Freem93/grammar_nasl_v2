#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include('compat.inc');

if (description)
{
  script_id(56057);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/07/14 14:23:28 $");

  script_cve_id(
    "CVE-2007-3853",
    "CVE-2007-3854",
    "CVE-2007-3855",
    "CVE-2007-3856",
    "CVE-2007-3857",
    "CVE-2007-3858",
    "CVE-2007-3859"
  );
  script_bugtraq_id(24887);
  script_osvdb_id(
    39974,
    39975,
    39976,
    39977,
    39978,
    39983,
    39984,
    39985,
    39986,
    39987,
    39989,
    39990,
    39991,
    39992,
    39993,
    39994,
    39996,
    39997
  );

  script_name(english:"Oracle Database Multiple Vulnerabilities (July 2007 CPU)");
  script_summary(english:"Checks installed patch info");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the July 2007
Critical Patch Update (CPU) and therefore is potentially affected by
security issues in the following components :

  - Advanced Queuing

  - DataGuard

  - JavaVM

  - Oracle Data Mining

  - Oracle Text

  - PL/SQL

  - Rules Manager

  - Spatial

  - SQL Compiler");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56ac783a");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2007 Oracle Critical
Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-516");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/17");
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
# JUL2007
patches = make_nested_array();

# RDBMS 10.1.0.5
patches["10.1.0.5"]["db"]["nix"] = make_array("patch_level", "10.1.0.5.7", "CPU", "6079585");
patches["10.1.0.5"]["db"]["win32"] = make_array("patch_level", "10.1.0.5.16", "CPU", "6115804");
# RDBMS 10.2.0.3
patches["10.2.0.3"]["db"]["nix"] = make_array("patch_level", "10.2.0.3.3", "CPU", "6079591");
patches["10.2.0.3"]["db"]["win32"] = make_array("patch_level", "10.2.0.3.8", "CPU", "6116131");
patches["10.2.0.3"]["db"]["win64"] = make_array("patch_level", "10.2.0.3.8", "CPU", "6116139");
# RDBMS 10.2.0.2
patches["10.2.0.2"]["db"]["nix"] = make_array("patch_level", "10.2.0.2.6", "CPU", "6079588");
patches["10.2.0.2"]["db"]["win32"] = make_array("patch_level", "10.2.0.2.8", "CPU", "6013105");
patches["10.2.0.2"]["db"]["win64"] = make_array("patch_level", "10.2.0.2.8", "CPU", "6013121");

check_oracle_database(patches:patches, high_risk:TRUE);
