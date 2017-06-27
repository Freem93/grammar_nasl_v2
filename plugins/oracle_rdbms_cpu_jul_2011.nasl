#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include("compat.inc");

if (description)
{
  script_id(55632);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/07/14 14:23:28 $");

  script_cve_id(
    "CVE-2011-0811",
    "CVE-2011-0816",
    "CVE-2011-0822",
    "CVE-2011-0830",
    "CVE-2011-0831",
    "CVE-2011-0832",
    "CVE-2011-0835",
    "CVE-2011-0838",
    "CVE-2011-0848",
    "CVE-2011-0852",
    "CVE-2011-0870",
    "CVE-2011-0875",
    "CVE-2011-0876",
    "CVE-2011-0877",
    "CVE-2011-0879",
    "CVE-2011-0880",
    "CVE-2011-0881",
    "CVE-2011-0882",
    "CVE-2011-2230",
    "CVE-2011-2231",
    "CVE-2011-2232",
    "CVE-2011-2238",
    "CVE-2011-2239",
    "CVE-2011-2240",
    "CVE-2011-2242",
    "CVE-2011-2243",
    "CVE-2011-2244",
    "CVE-2011-2248",
    "CVE-2011-2253",
    "CVE-2011-2257"
  );
  script_bugtraq_id(
    48726,
    48727,
    48728,
    48729,
    48730,
    48731,
    48732,
    48733,
    48734,
    48735,
    48736,
    48737,
    48738,
    48739,
    48740,
    48741,
    48742,
    48743,
    48745,
    48746,
    48748,
    48749,
    48750,
    48751,
    48754,
    48760,
    48764,
    48794
  );
  script_osvdb_id(
    73924,
    73926,
    73927,
    73928,
    73929,
    73930,
    73931,
    73932,
    73933,
    73934,
    73935,
    73936,
    73937,
    73938,
    73939,
    73940,
    73941,
    73942,
    73943,
    73944,
    73945,
    73946,
    73947,
    73948,
    73949,
    73950,
    73951,
    73952,
    73953,
    73954,
    92783,
    92784
  );

  script_name(english:"Oracle Database Multiple Vulnerabilities (July 2011 CPU)");
  script_summary(english:"Checks installed patch info");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple
vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote Oracle database server is missing the July 2011 Critical
Patch Update (CPU) and therefore is potentially affected by security
issues in the following components :

  - Core RDBMS (CVE-2011-0832, CVE-2011-0835, CVE-2011-0838,
    CVE-2011-0880, CVE-2011-2230, CVE-2011-2239,
    CVE-2011-2243, CVE-2011-2253)

  - Content Management (CVE-2011-0882)

  - Database Target Type Menus (CVE-2011-2257)

  - SQL Performance Advisories/UIs (CVE-2011-2248)

  - Schema Management (CVE-2011-0870)

  - Security Framework (CVE-2011-0848, CVE-2011-2244)

  - Security Management (CVE-2011-0852)

  - Streams, AQ & Replication Management (CVE-2011-0822)

  - XML Developer Kit (CVE-2011-2231, CVE-2011-2232)

  - CMDB Metadata & Instance APIs (CVE-2011-0816)

  - EMCTL (CVE-2011-0875, CVE-2011-0881)

  - Enterprise Config Management (CVE-2011-0811,
    CVE-2011-0831)

  - Enterprise Manager Console (CVE-2011-0876)

  - Event Management (CVE-2011-0830)

  - Instance Management (CVE-2011-0877, CVE-2011-0879)

  - Database Vault (CVE-2011-2238)

  - Oracle Universal Installer (CVE-2011-2240)");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7c55943");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2011 Oracle Critical
Patch Update advisory.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/20");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"plugin_type", value:"local");
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
# JUL2011
patches = make_nested_array();

# RDBMS 11.1.0.7
patches["11.1.0.7"]["db"]["nix"] = make_array("patch_level", "11.1.0.7.8", "CPU", "12419265, 12419384");
patches["11.1.0.7"]["db"]["win32"] = make_array("patch_level", "11.1.0.7.41", "CPU", "12695277");
patches["11.1.0.7"]["db"]["win64"] = make_array("patch_level", "11.1.0.7.41", "CPU", "12695278");
# RDBMS 11.2.0.2
patches["11.2.0.2"]["db"]["nix"] = make_array("patch_level", "11.2.0.2.3", "CPU", "12419321, 12419331");
patches["11.2.0.2"]["db"]["win32"] = make_array("patch_level", "11.2.0.2.8", "CPU", "12714462");
patches["11.2.0.2"]["db"]["win64"] = make_array("patch_level", "11.2.0.2.8", "CPU", "12714463");
# RDBMS 11.2.0.1
patches["11.2.0.1"]["db"]["nix"] = make_array("patch_level", "11.2.0.1.6", "CPU", "12419278, 12419378");
patches["11.2.0.1"]["db"]["win32"] = make_array("patch_level", "11.2.0.1.13", "CPU", "12429528");
patches["11.2.0.1"]["db"]["win64"] = make_array("patch_level", "11.2.0.1.13", "CPU", "12429529");
# RDBMS 10.1.0.5
patches["10.1.0.5"]["db"]["nix"] = make_array("patch_level", "10.1.0.5.22", "CPU", "12419228");
patches["10.1.0.5"]["db"]["win32"] = make_array("patch_level", "10.1.0.5.42", "CPU", "12429517");
# RDBMS 10.2.0.5
patches["10.2.0.5"]["db"]["nix"] = make_array("patch_level", "10.2.0.5.4", "CPU", "12419258, 12419392");
patches["10.2.0.5"]["db"]["win32"] = make_array("patch_level", "10.2.0.5.10", "CPU", "12429523");
patches["10.2.0.5"]["db"]["win64"] = make_array("patch_level", "10.2.0.5.10", "CPU", "12429524");
# RDBMS 10.2.0.4
patches["10.2.0.4"]["db"]["nix"] = make_array("patch_level", "10.2.0.4.9", "CPU", "12419249, 12419397");
patches["10.2.0.4"]["db"]["win32"] = make_array("patch_level", "10.2.0.4.45", "CPU", "12429519");
patches["10.2.0.4"]["db"]["win64"] = make_array("patch_level", "10.2.0.4.45", "CPU", "12429521");

check_oracle_database(patches:patches, high_risk:TRUE);
