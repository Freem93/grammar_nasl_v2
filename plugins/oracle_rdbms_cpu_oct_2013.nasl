#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include("compat.inc");

if (description)
{
  script_id(70460);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/07 18:00:12 $");

  script_cve_id(
    "CVE-2011-3389",
    "CVE-2013-0169",
    "CVE-2013-3826",
    "CVE-2013-5771"
  );
  script_bugtraq_id(
    49778,
    57778,
    63044,
    63046
  );
  script_osvdb_id(
    74829,
    89848,
    98514,
    98515
  );
  script_xref(name:"CERT", value:"864643");

  script_name(english:"Oracle Database Multiple Vulnerabilities (October 2013 CPU) (BEAST)");
  script_summary(english:"Checks installed patch info");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the October 2013 Critical
Patch Update (CPU). It is, therefore, affected by multiple security
vulnerabilities in the following components :

  - Core RDBMS
  - Oracle Security service
  - XML Parser");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac29c174");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2011/09/23/chromeandbeast.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/tls-cbc.txt");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2013 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
# OCT2013
patches = make_nested_array();

# RDBMS 11.1.0.7
patches["11.1.0.7"]["db"]["nix"] = make_array("patch_level", "11.1.0.7.17", "CPU", "17082374, 17082366");
patches["11.1.0.7"]["db"]["win32"] = make_array("patch_level", "11.1.0.7.54", "CPU", "17363759");
patches["11.1.0.7"]["db"]["win64"] = make_array("patch_level", "11.1.0.7.54", "CPU", "17363760");
# RDBMS 12.1.0.1
patches["12.1.0.1"]["db"]["nix"] = make_array("patch_level", "12.1.0.1.1", "CPU", "17027533");
patches["12.1.0.1"]["db"]["win32"] = make_array("patch_level", "12.1.0.1.1", "CPU", "17363795");
patches["12.1.0.1"]["db"]["win64"] = make_array("patch_level", "12.1.0.1.1", "CPU", "17363796");
# RDBMS 11.2.0.2
patches["11.2.0.2"]["db"]["nix"] = make_array("patch_level", "11.2.0.2.12", "CPU", "17082375, 17082367");
patches["11.2.0.2"]["db"]["win32"] = make_array("patch_level", "11.2.0.2.27", "CPU", "17363837");
patches["11.2.0.2"]["db"]["win64"] = make_array("patch_level", "11.2.0.2.27", "CPU", "17363838");
# RDBMS 11.2.0.3
patches["11.2.0.3"]["db"]["nix"] = make_array("patch_level", "11.2.0.3.8", "CPU", "17082364, 16902043");
patches["11.2.0.3"]["db"]["win32"] = make_array("patch_level", "11.2.0.3.25", "CPU", "17363844");
patches["11.2.0.3"]["db"]["win64"] = make_array("patch_level", "11.2.0.3.25", "CPU", "17363850");

check_oracle_database(patches:patches);
