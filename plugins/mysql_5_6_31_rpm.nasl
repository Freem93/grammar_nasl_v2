#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91996);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/01/23 17:47:51 $");

  script_cve_id(
    "CVE-2016-2105",
    "CVE-2016-3452",
    "CVE-2016-3459",
    "CVE-2016-3471",
    "CVE-2016-3477",
    "CVE-2016-3486",
    "CVE-2016-3501",
    "CVE-2016-3521",
    "CVE-2016-3614",
    "CVE-2016-3615",
    "CVE-2016-5439",
    "CVE-2016-5440",
    "CVE-2016-5444",
    "CVE-2016-8288"
  );
  script_bugtraq_id(
    89757,
    91902,
    91913,
    91932,
    91943,
    91949,
    91953,
    91960,
    91969,
    91980,
    91987,
    91992,
    91999,
    93740
  );
  script_osvdb_id(
    137899,
    139552,
    139553,
    139554,
    139555,
    139556,
    141885,
    141886,
    141887,
    141889,
    141891,
    141892,
    141894,
    141897,
    141898,
    141902,
    141903,
    141904,
    146000
  );

  script_name(english:"Oracle MySQL 5.6.x < 5.6.31 Multiple Vulnerabilities");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.6.x prior to
5.6.31. It is, therefore, affected by multiple vulnerabilities :

  - A heap buffer overflow condition exists in the
    EVP_EncodeUpdate() function within file
    crypto/evp/encode.c that is triggered when handling
    a large amount of input data. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition. (CVE-2016-2105)

  - An unspecified flaw exists in the Security: Encryption
    subcomponent that allows an unauthenticated, remote
    attacker to disclose sensitive information.
    (CVE-2016-3452)

  - An unspecified flaw exists in the InnoDB subcomponent
    that allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-3459)

  - An unspecified flaw exists in the Options subcomponent
    that allows a local attacker to gain elevated
    privileges. (CVE-2016-3471)

  - An unspecified flaw exists in the Parser subcomponent
    that allows a local attacker to gain elevated
    privileges. (CVE-2016-3477)

  - An unspecified flaw exists in the FTS subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-3486)

  - An unspecified flaw exists in the Optimizer subcomponent
    that allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-3501)

  - An unspecified flaw exists in the Types subcomponent
    that allows an authenticated, remote attacker to cause
    a denial of service condition. (CVE-2016-3521)

  - An unspecified flaw exists in the Security: Encryption
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2016-3614)

  - An unspecified flaw exists in the DML subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-3615)

  - An unspecified flaw exists in the Privileges
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2016-5439)

  - An unspecified flaw exists in the RBR subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-5440)

  - An unspecified flaw exists in the Connection
    subcomponent that allows an unauthenticated, remote
    attacker to disclose sensitive information.
    (CVE-2016-5444)

  - An unspecified flaw exists in the InnoDB Plugin
    subcomponent that allows an authenticated, remote
    attacker to impact integrity. (CVE-2016-8288)

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

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?453b5f8c");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bac902d5");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-31.html");
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3089849.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42cde00c");
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3235388.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c523d145");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/rs?type=doc&id=2157431.1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.6.31 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");
  script_require_ports("Host/RedHat/release", "Host/AmazonLinux/release", "Host/SuSE/release", "Host/CentOS/release");

  exit(0);
}

include("mysql_version.inc");

fix_version = "5.6.31";
exists_version = "5.6";

mysql_check_rpms(mysql_packages:default_mysql_rpm_list_server_only, fix_ver:fix_version, exists_ver:exists_version, rhel_os_list:default_mysql_rhel_os_list, centos_os_list:default_mysql_centos_os_list, suse_os_list:default_mysql_suse_os_list, ala_os_list:default_mysql_ala_os_list, severity:SECURITY_HOLE);
