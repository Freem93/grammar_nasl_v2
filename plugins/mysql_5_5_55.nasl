#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99514);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/04/21 13:44:39 $");

  script_cve_id(
    "CVE-2017-3302",
    "CVE-2017-3305",
    "CVE-2017-3308",
    "CVE-2017-3309",
    "CVE-2017-3329",
    "CVE-2017-3453",
    "CVE-2017-3456",
    "CVE-2017-3461",
    "CVE-2017-3462",
    "CVE-2017-3463",
    "CVE-2017-3464",
    "CVE-2017-3600"
  );
  script_bugtraq_id(
    96162,
    97023,
    97725,
    97742,
    97763,
    97765,
    97776,
    97812,
    97818,
    97831,
    97849,
    97851
  );
  script_osvdb_id(
    151210,
    153996,
    155874,
    155875,
    155878,
    155879,
    155881,
    155888,
    155892,
    155893,
    155894,
    155895
  );
  script_xref(name:"IAVA", value:"2017-A-0118");

  script_name(english:"MySQL 5.5.x < 5.5.55 Multiple Vulnerabilities (April 2017 CPU) (Riddle)");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.5.x prior to
5.5.55. It is, therefore, affected by multiple vulnerabilities :

  - A use-after-free error exists in the
    mysql_prune_stmt_list() function in client.c that allows
    an authenticated, remote attacker to cause a denial of
    service condition. (CVE-2017-3302)

  - An authentication information disclosure vulnerability,
    known as Riddle, exists due to authentication being
    performed prior to security parameter verification. A
    man-in-the-middle (MitM) attacker can exploit this
    vulnerability to disclose sensitive authentication
    information, which the attacker can later use for
    authenticating to the server. (CVE-2017-3305)

  - Multiple unspecified flaws exist in the DML subcomponent
    that allow an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2017-3308,
    CVE-2017-3456)

  - Multiple unspecified flaws exist in the Optimizer
    subcomponent that allow an authenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2017-3309, CVE-2017-3453)

  - An unspecified flaw exists in the Thread Pooling
    subcomponent that allows an unauthenticated, remote
    attacker to update, insert, or delete data contained in
    the database. (CVE-2017-3329)

  - Multiple unspecified flaws exist in the
    'Security: Privileges' subcomponent that allow an
    authenticated, remote attacker to cause a denial of
    service condition. (CVE-2017-3461, CVE-2017-3462,
    CVE-2017-3463)

  - An unspecified flaw exists in the DDL subcomponent that
    allows an authenticated, remote attacker to update,
    insert, or delete data contained in the database.
    (CVE-2017-3464)

  - An unspecified flaw exists in the 'Client mysqldump'
    subcomponent that allows an authenticated, remote
    attacker to execute arbitrary code. (CVE-2017-3600)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-55.html");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54d9438d");
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3681811.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08e1362c");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/rs?type=doc&id=2244179.1");
  script_set_attribute(attribute:"see_also", value:"http://riddle.link/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.5.55 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:'5.5.55', min:'5.5', severity:SECURITY_HOLE);
