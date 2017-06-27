#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include("compat.inc");

if (description)
{
  script_id(99480);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/22 20:40:13 $");

  script_cve_id(
    "CVE-2017-3486",
    "CVE-2017-3567"
  );
  script_bugtraq_id(
    97870,
    97873
  );
  script_osvdb_id(
    155725,
    155726
  );
  script_xref(name:"IAVA", value:"2017-A-0112");

  script_name(english:"Oracle Database Multiple Vulnerabilities (April 2017 CPU)");
  script_summary(english:"Checks installed patch info");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Database Server is missing the April 2017 Critical
Patch Update (CPU). It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified flaw exists in the SQL*Plus component
    that allows a local attacker to impact confidentiality,
    integrity, and availability. (CVE-2017-3486)

  - An unspecified flaw exists in the OJVM component that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2017-3567)");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?623d2c22");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2017 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date",value:"2017/04/18");
  script_set_attribute(attribute:"patch_publication_date",value:"2017/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/19");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include("global_settings.inc");
include("oracle_rdbms_cpu_func.inc");
include("misc_func.inc");

patches = make_nested_array();

# RDBMS 12.1.0.2
patches["12.1.0.2"]["db"]["nix"] = make_array("patch_level", "12.1.0.2.170418", "CPU", "25171037, 25433352");
patches["12.1.0.2"]["db"]["win"] = make_array("patch_level", "12.1.0.2.170418", "CPU", "25632533");
# RDBMS 11.2.0.4 #
patches["11.2.0.4"]["db"]["nix"] = make_array("patch_level", "11.2.0.4.170418", "CPU", "25369547, 24732075");
patches["11.2.0.4"]["db"]["win"] = make_array("patch_level", "11.2.0.4.170418", "CPU", "25632525");

# JVM 12.1.0.2
patches["12.1.0.2"]["ojvm"]["nix"] = make_array("patch_level", "12.1.0.2.170418", "CPU", "25437695");
patches["12.1.0.2"]["ojvm"]["win"] = make_array("patch_level", "12.1.0.2.170418", "CPU", "25590993");
# JVM 11.2.0.4
patches["11.2.0.4"]["ojvm"]["nix"] = make_array("patch_level", "11.2.0.4.170418", "CPU", "25434033");
patches["11.2.0.4"]["ojvm"]["win"] = make_array("patch_level", "11.2.0.4.170418", "CPU", "25590979");

check_oracle_database(patches:patches, high_risk:TRUE);
