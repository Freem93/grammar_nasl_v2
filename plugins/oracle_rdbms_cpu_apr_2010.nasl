#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include("compat.inc");

if (description)
{
  script_id(45626);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2015/07/14 14:23:28 $");

  script_cve_id(
    "CVE-2010-0851",
    "CVE-2010-0852",
    "CVE-2010-0854",
    "CVE-2010-0860",
    "CVE-2010-0866",
    "CVE-2010-0867"
  );
  script_bugtraq_id(39421, 39424, 39427, 39428, 39434, 39439);
  script_osvdb_id(62184, 63767, 63769, 63770, 63771, 63773);

  script_name(english:"Oracle Database Multiple Vulnerabilities (April 2010 CPU)");
  script_summary(english:"Checks installed patch info");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the April 2010 Critical
Patch Update (CPU) and therefore is potentially affected by security
issues in the following components :

  - Core RDBMS

  - JavaVM

  - Change Data Capture

  - Audit");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c8d409ef");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2010 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-209");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include("global_settings.inc");
include("oracle_rdbms_cpu_func.inc");
include("misc_func.inc");

################################################################################
# APR2010
patches = make_nested_array();

# RDBMS 11.1.0.7
patches["11.1.0.7"]["db"]["nix"] = make_array("patch_level", "11.1.0.7.3", "CPU", "9369783, 9352179");
patches["11.1.0.7"]["db"]["win32"] = make_array("patch_level", "11.1.0.7.25", "CPU", "9392331");
patches["11.1.0.7"]["db"]["win64"] = make_array("patch_level", "11.1.0.7.25", "CPU", "9392335");
# RDBMS 11.2.0.1
patches["11.2.0.1"]["db"]["nix"] = make_array("patch_level", "11.2.0.1.1", "CPU", "9369797, 9352237");
# RDBMS 10.1.0.5
patches["10.1.0.5"]["db"]["nix"] = make_array("patch_level", "10.1.0.5.18", "CPU", "9352208");
patches["10.1.0.5"]["db"]["win32"] = make_array("patch_level", "10.1.0.5.38", "CPU", "9390288");
# RDBMS 10.2.0.4
patches["10.2.0.4"]["db"]["nix"] = make_array("patch_level", "10.2.0.4.4", "CPU", "9352191, 9352164");
patches["10.2.0.4"]["db"]["win32"] = make_array("patch_level", "10.2.0.4.34", "CPU", "9393548");
patches["10.2.0.4"]["db"]["win64"] = make_array("patch_level", "10.2.0.4.34", "CPU", "9393550");

check_oracle_database(patches:patches, high_risk:TRUE);
