#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93002);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/23 17:47:51 $");

  script_cve_id(
    "CVE-2016-5612",
    "CVE-2016-5627",
    "CVE-2016-5630",
    "CVE-2016-8284"
  );
  script_bugtraq_id(
    93630,
    93642,
    93674,
    93755
  );
  script_osvdb_id(
    142918,
    142919,
    145980,
    145982,
    145988,
    146002
  );

  script_name(english:"MySQL 5.6.x < 5.6.32 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.6.x prior to
5.6.32. It is, therefore, affected by multiple vulnerabilities :

  - An unspecified flaw exists in the DML subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-5612)

  - Multiple unspecified flaws exist in the InnoDB
    subcomponent that allow an authenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2016-5627, CVE-2016-5630)

  - An unspecified flaw exists in the Replication
    subcomponent that allows a local attacker to cause a
    denial of service condition. (CVE-2016-8284)

  - A denial of service vulnerability exists in the
    NAME_CONST() function when handling certain unspecified
    arguments. An authenticated, remote attacker can exploit
    this to cause the server to exit. (VulnDB 142918)

  - A denial of service vulnerability exists in InnoDB when
    selecting full-text index information schema tables for
    a deleted table. An authenticated, remote attacker can
    exploit this to cause a segmentation fault.
    (VulnDB 142919)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bac902d5");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-32.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.6.32 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/17");

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

mysql_check_version(fixed:'5.6.32', min:'5.6', severity:SECURITY_WARNING);
