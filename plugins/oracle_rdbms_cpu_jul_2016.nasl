#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include("compat.inc");

if (description)
{
  script_id(92522);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/07 21:08:18 $");

  script_cve_id(
    "CVE-2015-0204",
    "CVE-2016-3448",
    "CVE-2016-3467",
    "CVE-2016-3479",
    "CVE-2016-3484",
    "CVE-2016-3488",
    "CVE-2016-3489",
    "CVE-2016-3506",
    "CVE-2016-3609"
  );
  script_bugtraq_id(
    71936,
    91842,
    91867,
    91874,
    91885,
    91890,
    91894,
    91898,
    91905
  );
  script_osvdb_id(
    116794,
    141713,
    141714,
    141715,
    141716,
    141717,
    141718,
    141719,
    141720
  );
  script_xref(name:"CERT", value:"243585");

  script_name(english:"Oracle Database Multiple Vulnerabilities (July 2016 CPU) (FREAK)");
  script_summary(english:"Checks the installed patch info.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Database Server is missing the July 2016 Critical
Patch Update (CPU). It is, therefore, affected by multiple
vulnerabilities :

  - A security feature bypass vulnerability, known as FREAK
    (Factoring attack on RSA-EXPORT Keys), exists in the
    RDBMS HTTPS Listener package due to the support of weak
    EXPORT_RSA cipher suites with keys less than or equal to
    512 bits. A man-in-the-middle attacker may be able to
    downgrade the SSL/TLS connection to use EXPORT_RSA
    cipher suites which can be factored in a short amount of
    time, allowing the attacker to intercept and decrypt the
    traffic. (CVE-2015-0204)

  - An unspecified vulnerability exists in the Application
    Express component that allows an unauthenticated, remote
    attacker to impact confidentiality and integrity.
    (CVE-2016-3448)

  - An unspecified vulnerability exists in the Application
    Express component that allows an unauthenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2016-3467)

  - An unspecified vulnerability exists in the Portable
    Clusterware component that allows an unauthenticated,
    remote attacker to cause a denial of service condition.
    (CVE-2016-3479)

  - An unspecified vulnerability exists in the Database
    Vault component that allows a local attacker to impact
    confidentiality and integrity. (CVE-2016-3484)

  - An unspecified vulnerability exists in the DB Sharding
    component that allows a local attacker to impact
    integrity. (CVE-2016-3488)

  - An unspecified vulnerability exists in the Data Pump
    Import component that allows a local attacker to to gain
    elevated privileges. (CVE-2016-3489)

  - An unspecified vulnerability exists in the JDBC
    component that allows an unauthenticated, remote
    attacker to execute arbitrary code. (CVE-2016-3506)

  - An unspecified vulnerability exists in the OJVM
    component that allows an authenticated, remote attacker
    to execute arbitrary code. (CVE-2016-3609)");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?453b5f8c");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2016 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("oracle_rdbms_query_patch_info.nbin", "oracle_rdbms_patch_info.nbin");

  exit(0);
}

include("global_settings.inc");
include("oracle_rdbms_cpu_func.inc");
include("misc_func.inc");

################################################################################
# JUL2016
patches = make_nested_array();

# RDBMS 12.1.0.2
patches["12.1.0.2"]["db"]["nix"] = make_array("patch_level", "12.1.0.2.160719", "CPU", "23054246, 23144544");
patches["12.1.0.2"]["db"]["win"] = make_array("patch_level", "12.1.0.2.160719", "CPU", "23530387");
# RDBMS 12.1.0.1 #
patches["12.1.0.1"]["db"]["nix"] = make_array("patch_level", "12.1.0.1.160719", "CPU", "23054354");
patches["12.1.0.1"]["db"]["win"] = make_array("patch_level", "12.1.0.1.160719", "CPU", "23530410");
# RDBMS 11.2.0.4 #
patches["11.2.0.4"]["db"]["nix"] = make_array("patch_level", "11.2.0.4.160719", "CPU", "23177648, 23054359");
patches["11.2.0.4"]["db"]["win"] = make_array("patch_level", "11.2.0.4.160719", "CPU", "23530402");

# JVM 12.1.0.2
patches["12.1.0.2"]["ojvm"]["nix"] = make_array("patch_level", "12.1.0.2.160719", "CPU", "23177536");
patches["12.1.0.2"]["ojvm"]["win"] = make_array("patch_level", "12.1.0.2.160719", "CPU", "23515290");
# JVM 12.1.0.1
patches["12.1.0.1"]["ojvm"]["nix"] = make_array("patch_level", "12.1.0.1.160719", "CPU", "23177541");
patches["12.1.0.1"]["ojvm"]["win"] = make_array("patch_level", "12.1.0.1.160719", "CPU", "23515285");
# JVM 11.2.0.4
patches["11.2.0.4"]["ojvm"]["nix"] = make_array("patch_level", "11.2.0.4.160719", "CPU", "23177551");
patches["11.2.0.4"]["ojvm"]["win"] = make_array("patch_level", "11.2.0.4.160719", "CPU", "23515277");

check_oracle_database(patches:patches, high_risk:TRUE);
