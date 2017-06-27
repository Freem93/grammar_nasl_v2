#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include('compat.inc');

if (description)
{
  script_id(56066);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/07/14 14:23:28 $");

  script_cve_id(
    "CVE-2009-1007",
    "CVE-2009-1018",
    "CVE-2009-1964",
    "CVE-2009-1965",
    "CVE-2009-1971",
    "CVE-2009-1972",
    "CVE-2009-1979",
    "CVE-2009-1985",
    "CVE-2009-1991",
    "CVE-2009-1992",
    "CVE-2009-1993",
    "CVE-2009-1994",
    "CVE-2009-1995",
    "CVE-2009-1997",
    "CVE-2009-2000",
    "CVE-2009-2001"
  );
  script_bugtraq_id(
    36742,
    36743,
    36744,
    36745,
    36747,
    36748,
    36750,
    36751,
    36752,
    36754,
    36755,
    36756,
    36758,
    36759,
    36760,
    36765
  );
  script_osvdb_id(
    59009,
    59098,
    59099,
    59101,
    59102,
    59103,
    59104,
    59105,
    59106,
    59107,
    59108,
    59109,
    59110,
    59111,
    59112,
    59113,
    59115
  );

  script_name(english:"Oracle Database Multiple Vulnerabilities (October 2009 CPU)");
  script_summary(english:"Checks installed patch info");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the October 2009
Critical Patch Update (CPU) and therefore is potentially affected by
security issues in the following components :

  - Advanced Queuing

  - Application Express

  - Auditing

  - Authentication

  - Core RDBMS

  - Data Mining

  - Data Pump

  - Network Authentication

  - Net Foundation Layer

  - Oracle Spatial

  - Oracle Text

  - PL/SQL

  - Workspace Manager");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc444d31");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2009 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Oracle 10gR2 TNS Listener AUTH_SESSKEY Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/20");
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
# OCT2009
patches = make_nested_array();

# RDBMS 11.1.0.7
patches["11.1.0.7"]["db"]["nix"] = make_array("patch_level", "11.1.0.7.1", "CPU", "8836375, 8833297");
patches["11.1.0.7"]["db"]["win32"] = make_array("patch_level", "11.1.0.7.3", "CPU", "8928976");
patches["11.1.0.7"]["db"]["win64"] = make_array("patch_level", "11.1.0.7.3", "CPU", "8928977");
# RDBMS 10.1.0.5
patches["10.1.0.5"]["db"]["nix"] = make_array("patch_level", "10.1.0.5.16", "CPU", "8836540");
patches["10.1.0.5"]["db"]["win32"] = make_array("patch_level", "10.1.0.5.36", "CPU", "8785211");
# RDBMS 10.2.0.4
patches["10.2.0.4"]["db"]["nix"] = make_array("patch_level", "10.2.0.4.2", "CPU", "8836308, 8833280");
patches["10.2.0.4"]["db"]["win32"] = make_array("patch_level", "10.2.0.4.26", "CPU", "8880857");
patches["10.2.0.4"]["db"]["win64"] = make_array("patch_level", "10.2.0.4.26", "CPU", "8880861");

check_oracle_database(patches:patches, high_risk:TRUE);
