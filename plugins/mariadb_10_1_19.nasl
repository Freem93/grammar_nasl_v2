#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95541);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/07 14:54:25 $");

  script_cve_id("CVE-2016-5584", "CVE-2016-7440");
  script_bugtraq_id(93735, 93659);
  script_osvdb_id(
    144833,
    145998,
    146531,
    146532,
    147133,
    147136
  );

  script_name(english:"MariaDB 10.1.x < 10.1.19 Multiple Vulnerabilities");
  script_summary(english:"Checks the MariaDB version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running on the remote host is 10.1.x prior to
10.1.19. It is, therefore, affected by multiple vulnerabilities :

  - An unspecified flaw exists in the Security: Encryption
    subcomponent that allows an authenticated, remote
    attacker to disclose sensitive information.
    (CVE-2016-5584)

  - A flaw exists in wolfSSL, specifically within the C
    software version of AES Encryption and Decryption, due
    to table lookups not properly considering cache-bank
    access times. A local attacker can exploit this, via a
    specially crafted application, to disclose AES keys.
    Note that this vulnerability does not affect MariaDB
    packages included in Red Hat products since they're
    built against system OpenSSL packages. (CVE-2016-7440)

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
    (VulnDB 146532)

  - A flaw exists in the buf_page_is_checksum_valid*
    functions in buf0buf.cc that is triggered during the
    handling of encrypted information. An authenticated,
    remote attacker can exploit this to crash the database,
    resulting in a denial of service condition.
    (VulnDB 147133)

  - A flaw exists in the wsrep_replicate_myisam
    functionality that is triggered when dropping MyISAM
    tables. An authenticated, remote attacker can exploit
    this to crash the database, resulting in a denial of
    service condition. (VulnDB 147136)");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb/mariadb-10119-changelog/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb/mariadb-10119-release-notes/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.1.19 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/07");
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

mysql_check_version(variant:'MariaDB', fixed:'10.1.19-MariaDB', min:'10.1', severity:SECURITY_WARNING);
