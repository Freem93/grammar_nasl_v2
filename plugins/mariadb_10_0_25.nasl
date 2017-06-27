#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91765);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/28 21:52:55 $");

  script_cve_id(
    "CVE-2016-0643",
    "CVE-2016-0647",
    "CVE-2016-0648",
    "CVE-2016-0655",
    "CVE-2016-0666",
    "CVE-2016-3452",
    "CVE-2016-3459",
    "CVE-2016-5444"
  );
  script_bugtraq_id(
    86424,
    86457,
    86486,
    86495,
    86509,
    91943,
    91987,
    91999
  );
  script_osvdb_id(
    136367,
    136375,
    137328,
    137336,
    137341,
    137344,
    137349,
    137977,
    137987,
    138000,
    138174,
    140239,
    141894,
    141902,
    141903
  );

  script_name(english:"MariaDB 10.0.x < 10.0.25 Multiple Vulnerabilities");
  script_summary(english:"Checks the MariaDB version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running on the remote host is 10.0.x prior to
10.0.25. It is, therefore, affected by multiple vulnerabilities :

  - An unspecified flaw exists in the DML subcomponent that
    allows an authenticated, remote attacker to disclose
    sensitive information. (CVE-2016-0643)

  - An unspecified flaw exists in the FTS subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0647)

  - An unspecified flaw exists in the PS subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0648)

  - An unspecified flaw exists in the InnoDB subcomponent
    that allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0655)

  - An unspecified flaw exists in the Security: Privileges
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2016-0666)

  - An unspecified flaw exists in the Encryption
    subcomponent that allows an unauthenticated, remote
    attacker to disclose sensitive information.
    (CVE-2016-3452)

  - An unspecified flaw in the InnoDB subcomponent allows an
    authenticated, remote attacker to cause a denial of
    service condition. (CVE-2016-3459)

  - An unspecified flaw in the Connection subcomponent
    allows an unauthenticated, remote attacker to disclose
    sensitive information. (CVE-2016-5444)

  - An overflow condition exists in the
    extension_based_table_discovery() function in
    discover.cc due to improper validation of user-supplied
    input. An authenticated, remote attacker can exploit
    this to cause a denial of service condition or the
    execution of arbitrary code. (VulnDB 136367)

  - A flaw exists in the mariadb_dyncol_unpack() function in
    ma_dyncol.c due to improper validation of user-supplied
    input. An authenticated, remote attacker can exploit
    this to corrupt memory, resulting in a denial of service
    condition or the execution of arbitrary code.
    (VulnDB 136375)

  - A flaw exists in the TDBTBM::ResetDB() function in
    tabtbl.cpp that is triggered when sorting a TBL table
    with a thread set to 'yes'. An authenticated, remote
    attacker can exploit this to crash the database,
    resulting in a denial of service condition.
    (VulnDB 137977)

  - A heap corruption issue exists in the
    handle_connections_shared_memory() function in mysqld.cc
    due to improper sanitization of user-supplied input. An
    authenticated, remote attacker can exploit this to crash
    the database, resulting in a denial of service
    condition. (VulnDB 137987)

  - An overflow condition exists in the
    ha_connect::ha_connect() function in ha_connect.cc due
    to improper validation of user-supplied input 
    when handling partnames. An authenticated, remote
    attacker can exploit this to cause a denial of service
    condition or the execution of arbitrary code.
    (VulnDB 138000)

  - An unspecified flaw exists in sql_insert.cc that is
    triggered during the handling of INSERT or REPLACE
    DELAYED statements. An authenticated, remote attacker
    can exploit this to crash the database, resulting in a
    denial of service condition. (VulnDB 138174)

  - A flaw exists in the Item_func_match::fix_index()
    function within file sql/item_func.cc due to improper
    handling of a full-text search of the utf8mb4 column.
    An authenticated, remote attacker can exploit this to
    crash the database, resulting in a denial of service
    condition. (VulnDB 140239)");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.org/mariadb-10-0-25-now-available/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb/mariadb-10025-changelog/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb/mariadb-10025-release-notes/");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-9986");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.0.25 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
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

mysql_check_version(variant:'MariaDB', fixed:'10.0.25-MariaDB', min:'10.0', severity:SECURITY_HOLE);
