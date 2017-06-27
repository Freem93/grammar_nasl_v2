#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91997);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/23 17:47:51 $");

  script_cve_id(
    "CVE-2016-2105",
    "CVE-2016-3424",
    "CVE-2016-3440",
    "CVE-2016-3452",
    "CVE-2016-3459",
    "CVE-2016-3477",
    "CVE-2016-3486",
    "CVE-2016-3501",
    "CVE-2016-3518",
    "CVE-2016-3521",
    "CVE-2016-3588",
    "CVE-2016-3614",
    "CVE-2016-3615",
    "CVE-2016-5436",
    "CVE-2016-5437",
    "CVE-2016-5439",
    "CVE-2016-5440",
    "CVE-2016-5441",
    "CVE-2016-5442",
    "CVE-2016-5443",
    "CVE-2016-5444",
    "CVE-2016-8288"
  );
  script_bugtraq_id(
    89757,
    91902,
    91906,
    91910,
    91915,
    91917,
    91932,
    91943,
    91949,
    91953,
    91960,
    91963,
    91967,
    91969,
    91974,
    91976,
    91980,
    91983,
    91987,
    91992,
    91999,
    93740
  );
  script_osvdb_id(
    137899,
    139551,
    139552,
    139553,
    139554,
    139555,
    139556,
    139558,
    139559,
    139560,
    139561,
    141884,
    141885,
    141886,
    141887,
    141888,
    141889,
    141890,
    141891,
    141892,
    141893,
    141894,
    141895,
    141896,
    141897,
    141898,
    141899,
    141900,
    141901,
    141902,
    141903,
    141904,
    146000
  );

  script_name(english:"MySQL 5.7.x < 5.7.13 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.7.x prior to
5.7.13. It is, therefore, affected by multiple vulnerabilities :

  - A heap buffer overflow condition exists in the
    EVP_EncodeUpdate() function within file
    crypto/evp/encode.c that is triggered when handling
    a large amount of input data. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition. (CVE-2016-2105)

  - Multiple unspecified flaws exist in the Optimizer
    subcomponent that allow an authenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2016-3424, CVE-2016-3440, CVE-2016-3501,
    CVE-2016-3518)

  - An unspecified flaw exists in the Security: Encryption
    subcomponent that allows an unauthenticated, remote
    attacker to disclose sensitive information.
    (CVE-2016-3452)

  - Multiple unspecified flaws exist in the InnoDB
    subcomponent that allow an authenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2016-3459, CVE-2016-5436)

  - An unspecified flaw exists in the Parser subcomponent
    that allows a local attacker to gain elevated
    privileges. (CVE-2016-3477)

  - An unspecified flaw exists in the FTS subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-3486)

  - An unspecified flaw exists in the Types subcomponent
    that allows an authenticated, remote attacker to cause
    a denial of service condition. (CVE-2016-3521)

  - An unspecified flaw exists in the InnoDB subcomponent
    that allows an authenticated, remote attacker to impact
    integrity and confidentiality. (CVE-2016-3588)

  - Multiple unspecified flaws exist in the Security:
    Encryption subcomponent that allow an authenticated,
    remote attacker to cause a denial of service condition.
    (CVE-2016-3614, CVE-2016-5442)

  - An unspecified flaw exists in the DML subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-3615)

  - An unspecified flaw exists in the Log subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-5437)

  - An unspecified flaw exists in the Privileges
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2016-5439)

  - An unspecified flaw exists in the RBR subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-5440)

  - An unspecified flaw exists in the Replication
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2016-5441)

  - An unspecified flaw exists in the Connection
    subcomponent that allows a local attacker to cause a
    denial of service condition. (CVE-2016-5443)

  - An unspecified flaw exists in the Connection
    subcomponent that allows an unauthenticated, remote
    attacker to disclose sensitive information.
    (CVE-2016-5444)

  - An unspecified flaw exists in the InnoDB Plugin
    subcomponent that allows an authenticated, remote
    attacker to impact integrity. (CVE-2016-8288)

  - Multiple flaws exist in InnoDB that are triggered when
    handling specially crafted 'ALTER TABLE' operations. An
    authenticated, remote attacker can exploit these issues
    to crash the database, resulting in a denial of service
    condition. (VulnDB 139551)

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

  - Multiple overflow conditions exist in the InnoDB
    memcached plugin due to improper validation of
    user-supplied input. An authenticated, remote attacker
    can exploit these issues to cause a denial of service
    condition or the execution of arbitrary code.
    (VulnDB 139554)

  - An unspecified flaw exists that is triggered when
    invoking Enterprise Encryption functions in multiple
    threads simultaneously or after creating and dropping
    them. An authenticated, remote attacker can exploit this
    to crash the database, resulting in a denial of service
    condition. (VulnDB 139555)

  - An unspecified flaw exists that is triggered when
    handling a 'SELECT ... GROUP BY ... FOR UPDATE' query
    executed with a loose index scan. An authenticated,
    remote attacker can exploit this to crash the database,
    resulting in a denial of service condition.
    (VulnDB 139556)

  - An unspecified flaw exists that is triggered when
    performing a 'FLUSH TABLES' operation on a table with a
    discarded tablespace. An authenticated, remote attacker
    can exploit this to crash the database, resulting in a
    denial of service condition. (VulnDB 139558)

  - A flaw exists in InnoDB that is triggered when
    performing an 'OPTIMIZE TABLE' operation on a table with
    a full-text index. An authenticated, remote attacker can
    exploit this to crash the database, resulting in a
    denial of service condition. (VulnDB 139559)

  - An unspecified flaw exists that is triggered when
    performing an UPDATE operation on a generated virtual
    BLOB column. An authenticated, remote attacker can
    exploit this to crash the database, resulting in a
    denial of service condition. (VulnDB 139560)

  - An unspecified flaw exists that is triggered when
    performing a 'SHOW CREATE TABLE' operation on a table
    with a generated column. An authenticated, remote
    attacker can exploit this to crash the database,
    resulting in a denial of service condition.
    (VulnDB 139561)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?453b5f8c");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bac902d5");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-13.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.7.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/20");

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

mysql_check_version(fixed:'5.7.13', min:'5.7', severity:SECURITY_HOLE);
