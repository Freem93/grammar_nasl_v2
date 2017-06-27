#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include("compat.inc");

if (description)
{
  script_id(63623);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/07/14 14:23:28 $");

  script_cve_id(
    "CVE-2012-3219",
    "CVE-2012-3220",
    "CVE-2012-5062",
    "CVE-2013-0352",
    "CVE-2013-0353",
    "CVE-2013-0354",
    "CVE-2013-0355",
    "CVE-2013-0358",
    "CVE-2013-0372",
    "CVE-2013-0373",
    "CVE-2013-0374"
  );
  script_bugtraq_id(
    57336,
    57349,
    57354,
    57361,
    57365,
    57368,
    57370,
    57372,
    57373,
    57378,
    57382
  );
  script_osvdb_id(
    89183,
    89198,
    89199,
    89200,
    89201,
    89202,
    89203,
    89204,
    89205,
    89206,
    89207
  );

  script_name(english:"Oracle Database Multiple Vulnerabilities (January 2013 CPU)");
  script_summary(english:"Checks installed patch info");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote Oracle database server is missing the January 2013 Critical
Patch Update (CPU) and is, therefore, potentially affected by security
issues in the following components :

  - Oracle Spatial

  - Enterprise Manager Base Platform"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525775/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525776/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525779/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525782/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525783/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525784/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525786/30/0/threaded");
  # http://www.oracle.com/technetwork/topics/security/cpujan2013-1515902.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b56cce0c");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2013 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/18");

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
# JAN2013
patches = make_nested_array();

# RDBMS 11.1.0.7
patches["11.1.0.7"]["db"]["nix"] = make_array("patch_level", "11.1.0.7.14", "CPU", "14841452, 14739378");
patches["11.1.0.7"]["db"]["win32"] = make_array("patch_level", "11.1.0.7.51", "CPU", "15848066");
patches["11.1.0.7"]["db"]["win64"] = make_array("patch_level", "11.1.0.7.51", "CPU", "15848067");
# RDBMS 11.2.0.2
patches["11.2.0.2"]["db"]["nix"] = make_array("patch_level", "11.2.0.2.9", "CPU", "14841437, 14727315");
patches["11.2.0.2"]["db"]["win32"] = make_array("patch_level", "11.2.0.2.23", "CPU", "16100398");
patches["11.2.0.2"]["db"]["win64"] = make_array("patch_level", "11.2.0.2.23", "CPU", "16100399");
# RDBMS 11.2.0.3
patches["11.2.0.3"]["db"]["nix"] = make_array("patch_level", "11.2.0.3.5", "CPU", "14841409, 14727310");
patches["11.2.0.3"]["db"]["win32"] = make_array("patch_level", "11.2.0.3.15", "CPU", "16042647");
patches["11.2.0.3"]["db"]["win64"] = make_array("patch_level", "11.2.0.3.15", "CPU", "16042648");
# RDBMS 10.2.0.5
patches["10.2.0.5"]["db"]["nix"] = make_array("patch_level", "10.2.0.5.10", "CPU", "14841459, 14727319");
patches["10.2.0.5"]["db"]["win32"] = make_array("patch_level", "10.2.0.5.20", "CPU", "15848060");
patches["10.2.0.5"]["db"]["win64"] = make_array("patch_level", "10.2.0.5.20", "CPU", "15848062");
# RDBMS 10.2.0.4
patches["10.2.0.4"]["db"]["nix"] = make_array("patch_level", "10.2.0.4.15", "CPU", "14841471, 14736542");

check_oracle_database(patches:patches, high_risk:TRUE);
