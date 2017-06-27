#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include('compat.inc');

if (description)
{
  script_id(56051);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/07 21:08:18 $");

  script_cve_id(
    "CVE-2006-0256",
    "CVE-2006-0257",
    "CVE-2006-0258",
    "CVE-2006-0259",
    "CVE-2006-0260",
    "CVE-2006-0261",
    "CVE-2006-0262",
    "CVE-2006-0263",
    "CVE-2006-0265",
    "CVE-2006-0266",
    "CVE-2006-0267",
    "CVE-2006-0268",
    "CVE-2006-0269",
    "CVE-2006-0270",
    "CVE-2006-0271",
    "CVE-2006-0272",
    "CVE-2006-0282",
    "CVE-2006-0283",
    "CVE-2006-0285",
    "CVE-2006-0290",
    "CVE-2006-0291",
    "CVE-2006-0435",
    "CVE-2006-0551",
    "CVE-2006-0547",
    "CVE-2006-0548",
    "CVE-2006-0549",
    "CVE-2006-0552",
    "CVE-2006-0586"
  );
  script_bugtraq_id(16287);
  script_osvdb_id(
    22539,
    22540,
    22541,
    22543,
    22544,
    22545,
    22546,
    22547,
    22549,
    22550,
    22551,
    22553,
    22555,
    22556,
    22557,
    22558,
    22559,
    22563,
    22565,
    22566,
    22567,
    22568,
    22569,
    22570,
    22573,
    22574,
    22575,
    22637,
    22639,
    22640,
    22641,
    22642,
    22643,
    22719,
    22839,
    22840,
    22919
  );

  script_name(english:"Oracle Database Multiple Vulnerabilities (January 2006 CPU)");
  script_summary(english:"Checks installed patch info");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the January 2006
Critical Patch Update (CPU) and therefore is potentially affected by
security issues in the following components :

  - Advanced Queuing

  - Change Data Capture

  - Connection Manager

  - Data Pump

  - Data Pump Metadata API

  - Dictionary

  - Java Net

  - Net Foundation Layer

  - Net Listener

  - Network Communications (RPC)

  - Oracle HTTP Server

  - Oracle Label Security

  - Oracle Text

  - Oracle Workflow Cartridge

  - Program Interface Network

  - Protocol Support

  - Query Optimizer

  - Reorganize Objects & Convert Tablespace

  - Security

  - Streams Apply

  - Streams Capture

  - Streams Subcomponent

  - TDE Wallet

  - Upgrade & Downgrade

  - XML Database");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa1ddec6");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2006 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-469");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_cwe_id(89, 310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/17");
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
# JAN2006
patches = make_nested_array();

# RDBMS 10.1.0.4
patches["10.1.0.4"]["db"]["nix"] = make_array("patch_level", "10.1.0.4.4", "CPU", "4751928");
patches["10.1.0.4"]["db"]["win32"] = make_array("patch_level", "10.1.0.4.9", "CPU", "4751259");
# RDBMS 10.1.0.5
patches["10.1.0.5"]["db"]["nix"] = make_array("patch_level", "10.1.0.5.1", "CPU", "4751932");
patches["10.1.0.5"]["db"]["win32"] = make_array("patch_level", "10.1.0.5.1", "CPU", "4882231");
# RDBMS 10.2.0.1
patches["10.2.0.1"]["db"]["nix"] = make_array("patch_level", "10.2.0.1.1", "CPU", "4751931");
patches["10.2.0.1"]["db"]["win32"] = make_array("patch_level", "10.2.0.1.3", "CPU", "4751539");
patches["10.2.0.1"]["db"]["win64"] = make_array("patch_level", "10.2.0.1.3", "CPU", "4770480");
# RDBMS 10.1.0.3
patches["10.1.0.3"]["db"]["nix"] = make_array("patch_level", "10.1.0.3.5", "CPU", "4751926");
patches["10.1.0.3"]["db"]["win32"] = make_array("patch_level", "10.1.0.3.11", "CPU", "4741077");

check_oracle_database(patches:patches, high_risk:TRUE);
