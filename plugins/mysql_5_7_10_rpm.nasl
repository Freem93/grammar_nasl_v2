#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88384);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/28 21:52:57 $");

  script_cve_id(
    "CVE-2016-0503",
    "CVE-2016-0504",
    "CVE-2016-0505",
    "CVE-2016-0546",
    "CVE-2016-0597",
    "CVE-2016-0598",
    "CVE-2016-0599",
    "CVE-2016-0600",
    "CVE-2016-0601",
    "CVE-2016-0606",
    "CVE-2016-0607",
    "CVE-2016-0608",
    "CVE-2016-0609",
    "CVE-2016-0611"
  );
  script_osvdb_id(
    133169,
    133170,
    133171,
    133174,
    133177,
    133178,
    133180,
    133181,
    133183,
    133184,
    133185,
    133186,
    133187,
    133190
  );

  script_name(english:"Oracle MySQL 5.7.x < 5.7.10 Multiple Vulnerabilities (January 2016 CPU)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle MySQL installed on the remote host is 5.7.x
prior to 5.7.10. It is, therefore, affected by the following
vulnerabilities :

  - An unspecified flaw exists in the Client subcomponent.
    A local attacker can exploit this to execute arbitrary
    code. (CVE-2016-0546)

  - An unspecified flaw exists in the Security:Encryption
    subcomponent. An authenticated, remote attacker can
    exploit this to impact integrity. (CVE-2016-0606)

Additionally, unspecified denial of service vulnerabilities exist in
the following MySQL subcomponents :

  - DML (CVE-2016-0503, CVE-2016-0504, CVE-2016-0598)

  - InnoDB (CVE-2016-0600)

  - Optimizer (CVE-2016-0597, CVE-2016-0599, CVE-2016-0611)

  - Options (CVE-2016-0505)

  - Partition (CVE-2016-0601)

  - Replication (CVE-2016-0607)

  - Security:Privileges (CVE-2016-0609)

  - UDF (CVE-2016-0608)");
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/2368796.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9afc74c4");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-10.html");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/rs?type=doc&id=2096144.1");
  # http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da1a16c5");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2016 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/26");

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

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");
  script_require_ports("Host/RedHat/release", "Host/AmazonLinux/release", "Host/SuSE/release", "Host/CentOS/release");

  exit(0);
}

include("mysql_version.inc");

package_list = make_list(
  "mysql-community-client",
  "mysql-community-common",
  "mysql-community-devel",
  "mysql-community-embedded",
  "mysql-community-libs",
  "mysql-community-libs-compat",
  "mysql-community-server",
  "MySQL-client",
  "MySQL-client-advanced",
  "MySQL-devel",
  "MySQL-devel-advanced",
  "MySQL-shared",
  "MySQL-shared-advanced",
  "MySQL-shared-compat",
  "MySQL-shared-compat-advanced",
  "MySQL-server",
  "MySQL-server-advanced"
);
rhel_list = make_list(
  "EL5",
  "EL6",
  "EL7",
  "FC20",
  "FC21",
  "FC22",
  "FC23",
  "RHEL5",
  "RHEL6",
  "RHEL7",
  "SL5",
  "SL6",
  "SL7"
);
ala_list = make_list(
  "ALA"
);
suse_list = make_list(
  "SLED11",
  "SLED12",
  "SLES11",
  "SLES12",
  "SUSE13.1",
  "SUSE13.2",
  "SUSE42.1"
);
centos_list = make_list(
  "CentOS-5",
  "CentOS-6",
  "CentOS-7"
);

fix_version = "5.7.10";
exists_version = "5.7";

mysql_check_rpms(mysql_packages:package_list, fix_ver:fix_version, exists_ver:exists_version, rhel_os_list:rhel_list, centos_os_list:centos_list, suse_os_list:suse_list, ala_os_list:ala_list, severity:SECURITY_HOLE);
