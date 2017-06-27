#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87420);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/28 21:52:57 $");

  script_cve_id(
    "CVE-2016-0503",
    "CVE-2016-0504",
    "CVE-2016-0505",
    "CVE-2016-0546",
    "CVE-2016-0595",
    "CVE-2016-0596",
    "CVE-2016-0597",
    "CVE-2016-0598",
    "CVE-2016-0600",
    "CVE-2016-0606",
    "CVE-2016-0607",
    "CVE-2016-0608",
    "CVE-2016-0609",
    "CVE-2016-0610",
    "CVE-2016-0611"
  );
  script_osvdb_id(
    131599,
    131601,
    131603,
    131610,
    131611,
    131612,
    131613,
    131614,
    131615,
    131616,
    133169,
    133170,
    133171,
    133173,
    133174,
    133175,
    133177,
    133178,
    133180,
    133181,
    133182,
    133185,
    133186,
    133187,
    133190
  );

  script_name(english:"MySQL 5.6.x < 5.6.28 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.6.x prior to
5.6.28. It is, therefore, affected by the following vulnerabilities :

  - Multiple unspecified flaws exists in the Server : DML
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service. (CVE-2016-0503,
    CVE-2016-0504, CVE-2016-0595, CVE-2016-0596)

  - An unspecified flaw exists in the Server : Options
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service. (CVE-2016-0505)

  - An unspecified flaw exists in the Client subcomponent
    that allows a local attacker to gain elevated
    privileges. (CVE-2016-0546)

  - Multiple unspecified flaws exist in the Server :
    Optimizer subcomponent that allows an authenticated,
    remote attacker to cause a denial of service.
    (CVE-2016-0597, CVE-2016-0598, CVE-2016-0611)

  - An unspecified flaw exists in the Server : InnoDB
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service.
    (CVE-2016-0600, CVE-2016-0610)

  - An unspecified flaw exists in the Server : Security :
    Encryption subcomponent that allows an authenticated,
    remote attacker to impact integrity. (CVE-2016-0606,
    CVE-2016-0609)

  - An unspecified flaw exists in the Server : Replication
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service. (CVE-2016-0607)

  - An unspecified flaw exists in the Server : UDF
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service. (CVE-2016-0608)

  - A denial of service vulnerability exists due to
    repeatedly executing a prepared statement when the
    default database has been changed. An authenticated,
    remote attacker can exploit this to cause the server
    to exit. (VulnDB 131599)

  - A denial of service vulnerability exists due to a flaw
    that is triggered when selecting DECIMAL values into
    user-defined variables. An authenticated, remote
    attacker can exploit this to cause the server to exit.
    (VulnDB 131601)

  - A flaw exists in the Server : InnoDB subcomponent due to
    a failure to check for destination files with the same
    name when using the ALTER TABLE operation to convert a
    table to an InnoDB file-per-table tablespace. An
    authenticated, remote attacker can exploit this to cause
    a denial of service. (VulnDB 131603)

  - A denial of service vulnerability exists that is
    triggered when updating views using ALL comparison
    operators on subqueries that select from indexed columns
    in the main table. An authenticated, remote attacker can
    exploit this to cause the server to exit, resulting in a
    denial of service condition. (VulnDB 131610)

  - A flaw exists in the Server : InnoDB subcomponent that
    is triggered when handling ALTER TABLE operations. An
    authenticated, remote attacker can exploit this to cause
    a denial of service condition. (VulnDB 131611)

  - A remote code execution vulnerability exists due to
    improper validation of user-supplied input to the
    strcpy() and sprintf() functions. An authenticated,
    remote attacker can exploit this to cause a buffer
    overflow, resulting in a denial of service condition or
    the execution of arbitrary code. (VulnDB 131612)

  - A denial of service vulnerability exists due to a flaw
    that is triggered when selecting DECIMAL values into
    user-defined variables. An authenticated, remote
    attacker can exploit this to cause the server to exit.
    (VulnDB 131613)
    
  - A denial of service vulnerability exists that is
    triggered when handling concurrent FLUSH PRIVILEGES and
    REVOKE or GRANT statements. An authenticated, remote
    attacker can exploit this to cause the server to exit by
    triggering an invalid memory access to proxy user
    information. (VulnDB 131614)

  - A denial of service vulnerability exists that is
    triggered on the second execution of a prepared
    statement where an ORDER BY clause references a column
    position. An authenticated, remote attacker can exploit
    this to cause the server to exit. (VulnDB 131615)

  - A denial of service vulnerability exists in the Server :
    Optimizer subcomponent due to accessing a stale pointer
    when handling filesorts for UPDATE statements. An
    authenticated, remote attacker can exploit this to cause
    to server to exit. (VulnDB 131616)");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-28.html");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75a4a4fb");
  # http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?66027465");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.6.28 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:'5.6.28', min:'5.6', severity:SECURITY_HOLE);
