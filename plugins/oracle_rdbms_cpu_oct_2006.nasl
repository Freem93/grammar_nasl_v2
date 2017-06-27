#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include('compat.inc');

if (description)
{
  script_id(56054);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/07/14 14:23:28 $");

  script_cve_id(
    "CVE-2006-5332",
    "CVE-2006-5333",
    "CVE-2006-5334",
    "CVE-2006-5335",
    "CVE-2006-5336",
    "CVE-2006-5337",
    "CVE-2006-5338",
    "CVE-2006-5339",
    "CVE-2006-5340",
    "CVE-2006-5341",
    "CVE-2006-5342",
    "CVE-2006-5343",
    "CVE-2006-5344",
    "CVE-2006-5345"
  );
  script_bugtraq_id(20588);
  script_osvdb_id(
    31427,
    31428,
    31429,
    31437,
    31446,
    31447,
    31448,
    31450,
    31451,
    31452,
    31453,
    31454,
    31455,
    31456,
    31457,
    31459,
    31460,
    31461,
    31462,
    31463
  );

  script_name(english:"Oracle Database Multiple Vulnerabilities (October 2006 CPU)");
  script_summary(english:"Checks installed patch info");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the October 2006
Critical Patch Update (CPU) and therefore is potentially affected by
security issues in the following components :

  - Change Data Capture (CDC)

  - Core RDBMS

  - Database Scheduler

  - Oracle Spatial

  - XMLDB");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?65b42037");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2006 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-486");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/17");
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
# OCT2006
patches = make_nested_array();

# RDBMS 10.1.0.4
patches["10.1.0.4"]["db"]["nix"] = make_array("patch_level", "10.1.0.4.7", "CPU", "5490844");
patches["10.1.0.4"]["db"]["win32"] = make_array("patch_level", "10.1.0.4.15", "CPU", "5500878");
# RDBMS 10.1.0.5
patches["10.1.0.5"]["db"]["nix"] = make_array("patch_level", "10.1.0.5.4", "CPU", "5490845");
patches["10.1.0.5"]["db"]["win32"] = make_array("patch_level", "10.1.0.5.8", "CPU", "5500883");
# RDBMS 10.2.0.2
patches["10.2.0.2"]["db"]["nix"] = make_array("patch_level", "10.2.0.2.3", "CPU", "5490848");
patches["10.2.0.2"]["db"]["win32"] = make_array("patch_level", "10.2.0.2.5", "CPU", "5502226");
patches["10.2.0.2"]["db"]["win64"] = make_array("patch_level", "10.2.0.2.5", "CPU", "5500921");
# RDBMS 10.2.0.1
patches["10.2.0.1"]["db"]["nix"] = make_array("patch_level", "10.2.0.1.4", "CPU", "5490846");
patches["10.2.0.1"]["db"]["win32"] = make_array("patch_level", "10.2.0.1.8", "CPU", "5500927");
patches["10.2.0.1"]["db"]["win64"] = make_array("patch_level", "10.2.0.1.8", "CPU", "5500954");
# RDBMS 10.1.0.3
patches["10.1.0.3"]["db"]["nix"] = make_array("patch_level", "10.1.0.3.8", "CPU", "5566825");

check_oracle_database(patches:patches, high_risk:TRUE);
