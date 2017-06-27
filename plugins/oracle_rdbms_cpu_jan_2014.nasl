#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include("compat.inc");

if (description)
{
  script_id(71970);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/07/14 14:23:28 $");

  script_cve_id(
    "CVE-2013-5764",
    "CVE-2013-5853",
    "CVE-2013-5858",
    "CVE-2014-0377",
    "CVE-2014-0378"
  );
  script_bugtraq_id(64811, 64812, 64817, 64820, 64824);
  script_osvdb_id(102079, 102080, 102081, 102082, 102083);

  script_name(english:"Oracle Database Multiple Vulnerabilities (January 2014 CPU)");
  script_summary(english:"Checks installed patch info");

  script_set_attribute(attribute:"synopsis", value:"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the January 2014 Critical
Patch Update (CPU) and is, therefore, potentially affected by security
issues in the following components :

  - Core RDBMS

  - Spatial");
  # http://www.oracle.com/technetwork/topics/security/cpujan2014-1972949.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17c46362");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2014 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include("global_settings.inc");
include("oracle_rdbms_cpu_func.inc");
include("misc_func.inc");

################################################################################
# JAN2014
patches = make_nested_array();

# RDBMS 11.1.0.7
patches["11.1.0.7"]["db"]["nix"] = make_array("patch_level", "11.1.0.7.18", "CPU", "17551415, 17465583");
patches["11.1.0.7"]["db"]["win32"] = make_array("patch_level", "11.1.0.7.55", "CPU", "17906935");
patches["11.1.0.7"]["db"]["win64"] = make_array("patch_level", "11.1.0.7.55", "CPU", "17906936");
# RDBMS 12.1.0.1
patches["12.1.0.1"]["db"]["nix"] = make_array("patch_level", "12.1.0.1.2", "CPU", "17552800");
patches["12.1.0.1"]["db"]["win"] = make_array("patch_level", "12.1.0.1.3", "CPU", "17977915");
# RDBMS 11.2.0.3
patches["11.2.0.3"]["db"]["nix"] = make_array("patch_level", "11.2.0.3.9", "CPU", "17478415, 17540582");
patches["11.2.0.3"]["db"]["win32"] = make_array("patch_level", "11.2.0.3.28", "CPU", "17906981");
patches["11.2.0.3"]["db"]["win64"] = make_array("patch_level", "11.2.0.3.28", "CPU", "18075406");
# RDBMS 11.2.0.4
patches["11.2.0.4"]["db"]["nix"] = make_array("patch_level", "11.2.0.4.1", "CPU", "17551709, 17478514");
patches["11.2.0.4"]["db"]["win"] = make_array("patch_level", "11.2.0.4.1", "CPU", "17987366");

check_oracle_database(patches:patches);
