#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95876);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/04/21 16:53:27 $");

  script_cve_id(
    "CVE-2017-3238",
    "CVE-2017-3243",
    "CVE-2017-3244",
    "CVE-2017-3258",
    "CVE-2017-3265",
    "CVE-2017-3291",
    "CVE-2017-3312",
    "CVE-2017-3313",
    "CVE-2017-3317",
    "CVE-2017-3318"
  );
  script_bugtraq_id(
    95491,
    95501,
    95520,
    95527,
    95538,
    95560,
    95565,
    95571,
    95585,
    95588
  );
  script_osvdb_id(
    148580,
    148581,
    148582,
    148583,
    150449,
    150450,
    150452,
    150454,
    150456,
    150457,
    150460,
    150461,
    150463,
    150464
  );

  script_name(english:"MySQL 5.5.x < 5.5.54 Multiple Vulnerabilities (January 2017 CPU)");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.5.x prior to
5.5.54. It is, therefore, affected by multiple vulnerabilities :

  - An unspecified flaw exists in the Optimizer subcomponent
    that allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2017-3238)

  - An unspecified flaw exists in the Charsets subcomponent
    that allows an authenticated, remote attacker to cause
    a denial of service condition. (CVE-2017-3243)

  - An unspecified flaw exists in the DML subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2017-3244)

  - An unspecified flaw exists in the DDL subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2017-3258)

  - An unspecified flaw exists in the Packaging subcomponent
    that allows a local attacker to impact confidentiality
    and availability. (CVE-2017-3265)

  - Multiple unspecified flaws exist in the Packaging
    subcomponent that allow a local attacker to gain
    elevated privileges. (CVE-2017-3291, CVE-2017-3312)

  - An unspecified flaw exists in the MyISAM subcomponent
    that allows a local attacker to disclose sensitive
    information. (CVE-2017-3313)

  - An unspecified flaw exists in the Logging subcomponent
    that allows a local attacker to cause a denial of
    service condition. (CVE-2017-3317)

  - An unspecified flaw exists in the Error Handling
    subcomponent that allows a local attacker to disclose
    sensitive information. (CVE-2017-3318)

  - A local privilege escalation vulnerability exists in the
    mysqld_safe component due to unsafe use of the 'rm' and
    'chown' commands. A local attacker can exploit this to
    gain elevated privileges. (VulnDB 148580)

  - An unspecified flaw exists in the mysqld_safe component
    that allows an authenticated, remote attacker to have an
    unspecified impact. (VulnDB 148581)

  - An overflow condition exists in the Optimizer component
    due to improper validation of user-supplied input when
    handling nested expressions. An authenticated, remote
    attacker can exploit this to cause a stack-based buffer
    overflow, resulting in a denial of service condition.
    (VulnDB 148582)

  - An unspecified flaw exists when handling a CREATE TABLE
    query with a DATA DIRECTORY clause. An authenticated,
    remote attacker can exploit this to gain elevated
    privileges. (VulnDB 148583)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-54.html");
  # http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1c38e52");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.5.54 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}
include("mysql_version.inc");

mysql_check_version(fixed:'5.5.54', min:'5.5', severity:SECURITY_HOLE);
