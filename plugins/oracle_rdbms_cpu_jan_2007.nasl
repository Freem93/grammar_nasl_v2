#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include('compat.inc');

if (description)
{
  script_id(56055);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/07 21:08:18 $");

  script_cve_id(
    "CVE-2007-0268",
    "CVE-2007-0269",
    "CVE-2007-0270",
    "CVE-2007-0271",
    "CVE-2007-0272",
    "CVE-2007-0273",
    "CVE-2007-0274",
    "CVE-2007-0275",
    "CVE-2007-0276",
    "CVE-2007-0277",
    "CVE-2007-0278"
  );
  script_bugtraq_id(22083);
  script_osvdb_id(
    32906,
    32907,
    32908,
    32909,
    32910,
    32911,
    32912,
    32913,
    32914,
    32915,
    32916,
    32917,
    32918,
    32919,
    32920,
    32921,
    32922
  );

  script_name(english:"Oracle Database Multiple Vulnerabilities (January 2007 CPU)");
  script_summary(english:"Checks installed patch info");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the January 2007
Critical Patch Update (CPU) and therefore is potentially affected by
security issues in the following components :

  - Advanced Queuing

  - Advanced Replication

  - Advanced Security Option

  - Change Data Capture

  - Data Guard

  - Export

  - Log Miner

  - NLS Runtime

  - Oracle Net Services

  - Oracle Spatial

  - Oracle Streams

  - Oracle Text

  - Oracle Workflow Cartridge

  - Recovery Manager

  - XMLDB");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08271da8");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2007 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-860");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_cwe_id(79, 119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include("global_settings.inc");
include("oracle_rdbms_cpu_func.inc");
include("misc_func.inc");

################################################################################
# JAN2007
patches = make_nested_array();

# RDBMS 10.1.0.4
patches["10.1.0.4"]["db"]["nix"] = make_array("patch_level", "10.1.0.4.8", "CPU", "5689894");
patches["10.1.0.4"]["db"]["win32"] = make_array("patch_level", "10.1.0.4.16", "CPU", "5695771");
# RDBMS 10.1.0.5
patches["10.1.0.5"]["db"]["nix"] = make_array("patch_level", "10.1.0.5.5", "CPU", "5689908");
patches["10.1.0.5"]["db"]["win32"] = make_array("patch_level", "10.1.0.5.11", "CPU", "5716295");
# RDBMS 10.2.0.3
patches["10.2.0.3"]["db"]["nix"] = make_array("patch_level", "10.2.0.3.1", "CPU", "5881721");
patches["10.2.0.3"]["db"]["win32"] = make_array("patch_level", "10.2.0.3.2", "CPU", "5846376");
patches["10.2.0.3"]["db"]["win64"] = make_array("patch_level", "10.2.0.3.2", "CPU", "5846378");
# RDBMS 10.2.0.2
patches["10.2.0.2"]["db"]["nix"] = make_array("patch_level", "10.2.0.2.4", "CPU", "5689957");
patches["10.2.0.2"]["db"]["win32"] = make_array("patch_level", "10.2.0.2.6", "CPU", "5716143");
patches["10.2.0.2"]["db"]["win64"] = make_array("patch_level", "10.2.0.2.6", "CPU", "5699839");
# RDBMS 10.2.0.1
patches["10.2.0.1"]["db"]["nix"] = make_array("patch_level", "10.2.0.1.5", "CPU", "5689937");
patches["10.2.0.1"]["db"]["win32"] = make_array("patch_level", "10.2.0.1.9", "CPU", "5695784");
patches["10.2.0.1"]["db"]["win64"] = make_array("patch_level", "10.2.0.1.9", "CPU", "5695786");
# RDBMS 10.1.0.3
patches["10.1.0.3"]["db"]["nix"] = make_array("patch_level", "10.1.0.3.9", "CPU", "5923277");

check_oracle_database(patches:patches, high_risk:TRUE);
