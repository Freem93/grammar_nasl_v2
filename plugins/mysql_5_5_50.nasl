#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91993);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/10/25 16:58:35 $");

  script_cve_id(
    "CVE-2016-3452",
    "CVE-2016-3471",
    "CVE-2016-3477",
    "CVE-2016-3521",
    "CVE-2016-3615",
    "CVE-2016-5440",
    "CVE-2016-5444"
  );
  script_bugtraq_id(
    91902,
    91913,
    91932,
    91953,
    91960,
    91987,
    91999
  );
  script_osvdb_id(
    139552,
    139553,
    141885,
    141889,
    141891,
    141898,
    141902,
    141903,
    141904
  );

  script_name(english:"MySQL 5.5.x < 5.5.50 Multiple Vulnerabilities (July 2016 CPU)");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.5.x prior to
5.5.50. It is, therefore, affected by multiple vulnerabilities :

  - An unspecified flaw exists in the Security: Encryption
    subcomponent that allows an unauthenticated, remote
    attacker to disclose potentially sensitive information.
    No other details are available. (CVE-2016-3452)

  - An unspecified flaw exists in the Options subcomponent
    that allows a local attacker to gain elevated
    privileges. No other details are available.
    (CVE-2016-3471)

  - An unspecified flaw exists in the Parser subcomponent
    that allows a local attacker to gain elevated
    privileges. No other details are available.
    (CVE-2016-3477)

  - An unspecified flaw exists in the Types subcomponent
    that allows an authenticated, remote attacker to cause
    a denial of service condition. No other details are
    available. (CVE-2016-3521)

  - An unspecified flaw exists in the DML subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. No other details are
    available. (CVE-2016-3615)

  - An unspecified flaw exists in the RBR subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. No other details are
    available. (CVE-2016-5440)

  - An unspecified flaw exists in the Connection
    subcomponent that allows an unauthenticated, remote
    attacker to disclose potentially sensitive information.
    No other details are available. (CVE-2016-5444)

  - Multiple overflow conditions exist due to improper
    validation of user-supplied input. An authenticated,
    remote attacker can exploit these issues to cause a
    denial of service condition or the execution of
    arbitrary code. (VulnDB 139552)

  - A NULL pointer dereference flaw exists in a parser
    structure that is triggered during the validation of
    stored procedure names. An authenticated, remote
    attacker can exploit this to crash the database,
    resulting in a denial of service condition.
    (VulnDB 139553)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?453b5f8c");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-50.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.5.50 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:'5.5.50', min:'5.5', severity:SECURITY_HOLE);
