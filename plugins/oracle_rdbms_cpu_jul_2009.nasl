
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include('compat.inc');

if (description)
{
  script_id(56065);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/07/14 14:23:28 $");

  script_cve_id(
    "CVE-2009-0987",
    "CVE-2009-1015",
    "CVE-2009-1019",
    "CVE-2009-1020",
    "CVE-2009-1021",
    "CVE-2009-1963",
    "CVE-2009-1966",
    "CVE-2009-1967",
    "CVE-2009-1968",
    "CVE-2009-1969",
    "CVE-2009-1970",
    "CVE-2009-1973"
  );
  script_bugtraq_id(
    35676,
    35677,
    35679,
    35680,
    35681,
    35682,
    35683,
    35684,
    35685,
    35687,
    35689,
    35692
  );
  script_osvdb_id(
    55884,
    55885,
    55886,
    55887,
    55888,
    55889,
    55890,
    55891,
    55892,
    55893,
    55894,
    55897
  );

  script_name(english:"Oracle Database Multiple Vulnerabilities (July 2009 CPU)");
  script_summary(english:"Checks installed patch info");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the July 2009 Critical
Patch Update (CPU) and therefore is potentially affected by security
issues in the following components :

  - Advanced Replication

  - Auditing

  - Config Management

  - Core RDBMS

  - Listener

  - Network Foundation

  - Secure Enterprise Search

  - Upgrade

  - Visual Private Database");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0096ebce");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2009 Oracle Critical
Patch Update advisory.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/14");
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
# JUL2009
patches = make_nested_array();

# RDBMS 11.1.0.7
patches["11.1.0.7"]["db"]["nix"] = make_array("patch_level", "11.1.0.7.0.2", "CPU", "8534338");
patches["11.1.0.7"]["db"]["win32"] = make_array("patch_level", "11.1.0.7.2", "CPU", "8553512");
patches["11.1.0.7"]["db"]["win64"] = make_array("patch_level", "11.1.0.7.2", "CPU", "8553515");
# RDBMS 11.1.0.6
patches["11.1.0.6"]["db"]["nix"] = make_array("patch_level", "11.1.0.6.7", "CPU", "8534378");
patches["11.1.0.6"]["db"]["win32"] = make_array("patch_level", "11.1.0.6.10", "CPU", "8563154");
patches["11.1.0.6"]["db"]["win64"] = make_array("patch_level", "11.1.0.6.10", "CPU", "8563155");
# RDBMS 10.1.0.5
patches["10.1.0.5"]["db"]["nix"] = make_array("patch_level", "10.1.0.5.15", "CPU", "8534394");
patches["10.1.0.5"]["db"]["win32"] = make_array("patch_level", "10.1.0.5.35", "CPU", "8656224");
# RDBMS 10.2.0.4
patches["10.2.0.4"]["db"]["nix"] = make_array("patch_level", "10.2.0.4.1", "CPU", "8534387, 8576156");
patches["10.2.0.4"]["db"]["win32"] = make_array("patch_level", "10.2.0.4.22", "CPU", "8559466");
patches["10.2.0.4"]["db"]["win64"] = make_array("patch_level", "10.2.0.4.22", "CPU", "8559467");

check_oracle_database(patches:patches, high_risk:TRUE);
