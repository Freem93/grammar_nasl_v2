#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76531);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/07/14 14:23:28 $");

  script_cve_id(
    "CVE-2013-3751",
    "CVE-2013-3774",
    "CVE-2014-4236",
    "CVE-2014-4237",
    "CVE-2014-4245"
  );
  script_bugtraq_id(61206, 61207, 68617, 68627, 68633);
  script_osvdb_id(95264, 95263);

  script_name(english:"Oracle Database Multiple Vulnerabilities (July 2014 CPU)");
  script_summary(english:"Checks the installed patch info.");

  script_set_attribute(attribute:"synopsis", value:"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the July 2014 Critical
Patch Update (CPU). It is, therefore, affected by security issues in
the following components :

  - XML Parser
  - Network Layer
  - RDBMS Core");
  # http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7de2f8eb");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2014 Oracle Critical
Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/16");

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
# JUL2014
patches = make_nested_array();

# RDBMS 11.1.0.7
patches["11.1.0.7"]["db"]["nix"] = make_array("patch_level", "11.1.0.7.20", "CPU", "18681875, 18522513");
patches["11.1.0.7"]["db"]["win32"] = make_array("patch_level", "11.1.0.7.57", "CPU", "18944207");
patches["11.1.0.7"]["db"]["win64"] = make_array("patch_level", "11.1.0.7.57", "CPU", "18944208");
# RDBMS 12.1.0.1
patches["12.1.0.1"]["db"]["nix"] = make_array("patch_level", "12.1.0.1.4", "CPU", "18522516");
patches["12.1.0.1"]["db"]["win"] = make_array("patch_level", "12.1.0.1.11", "CPU", "19062327");
# RDBMS 11.2.0.3
patches["11.2.0.3"]["db"]["nix"] = make_array("patch_level", "11.2.0.3.11", "CPU", "18681866, 18522512");
patches["11.2.0.3"]["db"]["win32"] = make_array("patch_level", "11.2.0.3.32", "CPU", "18940193");
patches["11.2.0.3"]["db"]["win64"] = make_array("patch_level", "11.2.0.3.32", "CPU", "18940194");
# RDBMS 11.2.0.4
patches["11.2.0.4"]["db"]["nix"] = make_array("patch_level", "11.2.0.4.3", "CPU", "18681862, 18522509");
patches["11.2.0.4"]["db"]["win"] = make_array("patch_level", "11.2.0.4.7", "CPU", "18842982");

check_oracle_database(patches:patches);
