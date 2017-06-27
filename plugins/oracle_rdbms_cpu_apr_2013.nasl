#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include("compat.inc");

if (description)
{
  script_id(65997);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/07/14 14:23:28 $");

  script_cve_id("CVE-2013-1534", "CVE-2013-1538", "CVE-2013-1554");
  script_bugtraq_id(59094, 59104, 59113);
  script_osvdb_id(92380, 92381, 92382);

  script_name(english:"Oracle Database Multiple Vulnerabilities (April 2013 CPU)");
  script_summary(english:"Checks installed patch info");

  script_set_attribute(attribute:"synopsis", value:"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote Oracle database server is missing the April 2013 Critical
Patch Update (CPU) and is, therefore, potentially affected by security
issues in the following components :

  - Workload Manager

  - Network Layer"
  );
  # http://www.oracle.com/technetwork/topics/security/cpuapr2013-1899555.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?028971b4");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2013 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include("global_settings.inc");
include("oracle_rdbms_cpu_func.inc");
include("misc_func.inc");

################################################################################
# APR2013
patches = make_nested_array();

# RDBMS 11.1.0.7
patches["11.1.0.7"]["db"]["nix"] = make_array("patch_level", "11.1.0.7.15", "CPU", "16308394, 16056268");
patches["11.1.0.7"]["db"]["win32"] = make_array("patch_level", "11.1.0.7.52", "CPU", "16345861");
patches["11.1.0.7"]["db"]["win64"] = make_array("patch_level", "11.1.0.7.52", "CPU", "16345862");
# RDBMS 11.2.0.2
patches["11.2.0.2"]["db"]["nix"] = make_array("patch_level", "11.2.0.2.10", "CPU", "16294412, 16056267");
patches["11.2.0.2"]["db"]["win32"] = make_array("patch_level", "11.2.0.2.25", "CPU", "16345845");
patches["11.2.0.2"]["db"]["win64"] = make_array("patch_level", "11.2.0.2.25", "CPU", "16345846");
# RDBMS 11.2.0.3
patches["11.2.0.3"]["db"]["nix"] = make_array("patch_level", "11.2.0.3.6", "CPU", "16294378, 16056266");
patches["11.2.0.3"]["db"]["win32"] = make_array("patch_level", "11.2.0.3.18", "CPU", "16345833");
patches["11.2.0.3"]["db"]["win64"] = make_array("patch_level", "11.2.0.3.18", "CPU", "16345834");
# RDBMS 10.2.0.5
patches["10.2.0.5"]["db"]["nix"] = make_array("patch_level", "10.2.0.5.11", "CPU", "16270946, 16056270");
patches["10.2.0.5"]["db"]["win32"] = make_array("patch_level", "10.2.0.5.21", "CPU", "16345855");
patches["10.2.0.5"]["db"]["win64"] = make_array("patch_level", "10.2.0.5.21", "CPU", "16345857");
# RDBMS 10.2.0.4
patches["10.2.0.4"]["db"]["nix"] = make_array("patch_level", "10.2.0.4.16", "CPU", "16270931, 16056269");

check_oracle_database(patches:patches, high_risk:TRUE);
