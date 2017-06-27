#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95540);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/07 14:54:25 $");

  script_cve_id(
    "CVE-2016-3492",
    "CVE-2016-5584",
    "CVE-2016-5616",
    "CVE-2016-5624",
    "CVE-2016-5626",
    "CVE-2016-5629",
    "CVE-2016-6663",
    "CVE-2016-7440",
    "CVE-2016-8283"
  );
  script_bugtraq_id(
    92911,
    93614,
    93635,
    93638,
    93650,
    93659,
    93668,
    93735,
    93737
  );
  script_osvdb_id(
    144202,
    144428,
    144429,
    144833,
    145976,
    145979,
    145981,
    145983,
    145986,
    145998,
    145999,
    146531, 
    146532
  );
  script_xref(name:"EDB-ID", value:"40678");

  script_name(english:"MariaDB 10.0.x < 10.0.28 Multiple Vulnerabilities");
  script_summary(english:"Checks the MariaDB version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running on the remote host is 10.0.x prior to
10.0.28. It is, therefore, affected by multiple vulnerabilities :

  - An unspecified flaw exists in the Optimizer subcomponent
    that allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-3492)

  - An unspecified flaw exists in the Security: Encryption
    subcomponent that allows an authenticated, remote
    attacker to disclose sensitive information.
    (CVE-2016-5584)

  - An unspecified flaw exists in the MyISAM subcomponent
    that allows a local attacker to gain elevated
    privileges. (CVE-2016-5616)

  - An unspecified flaw exists in the DML subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-5624)

  - An unspecified flaw exists in the GIS subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-5626)

  - An unspecified flaw exists in the Federated subcomponent
    that allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-5629)

  - An unspecified flaw exists that allows an authenticated,
    remote attacker to bypass restrictions and create the
    /var/lib/mysql/my.cnf file with custom contents without
    the FILE privilege requirement. (CVE-2016-6663)

  - A flaw exists in wolfSSL, specifically within the C
    software version of AES Encryption and Decryption, due
    to table lookups not properly considering cache-bank
    access times. A local attacker can exploit this, via a
    specially crafted application, to disclose AES keys.
    Note that this vulnerability does not affect MariaDB
    packages included in Red Hat products since they're
    built against system OpenSSL packages. (CVE-2016-7440)

  - An unspecified flaw exists in the Types subcomponent
    that allows an authenticated, remote attacker to cause
    a denial of service condition. (CVE-2016-8283)

  - A flaw exists in the fix_after_pullout() function in
    item.cc that is triggered when handling a prepared
    statement with a conversion to semi-join. An
    authenticated, remote attacker can exploit this to crash
    the database, resulting in a denial of service
    condition. (VulnDB 144428)

  - A flaw exists in the mysql_admin_table() function in
    sql_admin.cc that is triggered when handling
    re-execution of certain ANALYZE TABLE prepared
    statements. An authenticated, remote attacker can
    exploit this to crash the database, resulting in a
    denial of service condition. (VulnDB 144429)

  - A flaw exists in the fill_alter_inplace_info() function
    in sql_table.cc that is triggered when altering 
    persistent virtual columns. An authenticated, remote
    attacker can exploit this to crash the database,
    resulting in a denial of service condition.
    (VulnDB 146531)

  - A flaw exists in the mysql_rm_table_no_locks() function
    in sql_table.cc that is triggered during the handling of
    CREATE OR REPLACE TABLE queries. An authenticated,
    remote attacker can exploit this to crash the database,
    resulting in a denial of service condition.
    (VulnDB 146532)");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb/mariadb-10028-changelog/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb/mariadb-10028-release-notes/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.0.28 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
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

mysql_check_version(variant:'MariaDB', fixed:'10.0.28-MariaDB', min:'10.0', severity:SECURITY_WARNING);
