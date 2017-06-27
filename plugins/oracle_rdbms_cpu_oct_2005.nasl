#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include('compat.inc');

if (description)
{
  script_id(56050);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/07/14 14:23:28 $");

  script_cve_id(
    "CVE-2005-3202",
    "CVE-2005-3203",
    "CVE-2005-3204",
    "CVE-2005-3205",
    "CVE-2005-3206",
    "CVE-2005-3207"
  );
  script_bugtraq_id(
    15030,
    15031,
    15032,
    15033,
    15034,
    15039
  );
  script_osvdb_id(
    20051,
    20052,
    20053,
    20054,
    20055,
    20056,
    20063
  );

  script_name(english:"Oracle Database Multiple Vulnerabilities (October 2005 CPU)");
  script_summary(english:"Checks installed patch info");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the October 2005
Critical Patch Update (CPU) and therefore is potentially affected by
security issues in the following components :

  - Change Data Capture

  - Data Guard Logical Standby

  - Data Pump Export

  - Database Scheduler

  - Export

  - Locale

  - Materialized Views

  - Objects Extension

  - Oracle HTTP Server

  - Oracle Intelligent Agent

  - Oracle Internet Directory

  - Oracle Label Security

  - Oracle Security Service

  - Oracle Single Sign-On

  - Oracle Spatial

  - Oracle Workflow Cartridge

  - PL/SQL

  - Programmatic Interface

  - Security

  - Workspace Manager");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5b299b4");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2005 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/18");
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
# OCT2005
patches = make_nested_array();

# RDBMS 10.1.0.4
patches["10.1.0.4"]["db"]["nix"] = make_array("patch_level", "10.1.0.4.3", "CPU", "4567866");
patches["10.1.0.4"]["db"]["win32"] = make_array("patch_level", "10.1.0.4.6", "CPU", "4579182");
# RDBMS 10.1.0.3
patches["10.1.0.3"]["db"]["nix"] = make_array("patch_level", "10.1.0.3.4", "CPU", "4567863");
patches["10.1.0.3"]["db"]["win32"] = make_array("patch_level", "10.1.0.3.10", "CPU", "4567518");

check_oracle_database(patches:patches);
