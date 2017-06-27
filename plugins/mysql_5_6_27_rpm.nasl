#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86661);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/10/25 16:58:35 $");

  script_cve_id(
    "CVE-2015-4791",
    "CVE-2015-4792",
    "CVE-2015-4800",
    "CVE-2015-4802",
    "CVE-2015-4815",
    "CVE-2015-4826",
    "CVE-2015-4830",
    "CVE-2015-4836",
    "CVE-2015-4858",
    "CVE-2015-4861",
    "CVE-2015-4862",
    "CVE-2015-4870",
    "CVE-2015-4890",
    "CVE-2015-4910",
    "CVE-2015-4913",
    "CVE-2015-7744",
    "CVE-2016-0605",
    "CVE-2016-3471"
  );
  script_bugtraq_id(
    77137,
    77145,
    77147,
    77153,
    77165,
    77171,
    77190,
    77208,
    77213,
    77216,
    77222,
    77228,
    77231,
    77234,
    77237,
    91618
  );
  script_osvdb_id(
    129165,
    129167,
    129169,
    129172,
    129173,
    129174,
    129176,
    129177,
    129179,
    129181,
    129183,
    129184,
    129186,
    129187,
    129189,
    133188,
    133189,
    141885
  );

  script_name(english:"Oracle MySQL 5.6.x < 5.6.27 Multiple Vulnerabilities (October 2015 CPU) (January 2016 CPU) (July 2016 CPU)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle MySQL installed on the remote host is 5.6.x
prior to 5.6.27. It is, therefore, affected by the following
vulnerabilities :

  - An unspecified flaw exists in the Types subcomponent.
    An authenticated, remote attacker can exploit this to
    gain access to sensitive information. (CVE-2015-4826)

  - An unspecified flaw exists in the Security:Privileges
    subcomponent. An authenticated, remote attacker can
    exploit this to impact integrity. (CVE-2015-4830)

  - An unspecified flaw exists in the Security:Encryption
    subcomponent. An unauthenticated, remote attacker can
    exploit this to gain access to sensitive information.
    (CVE-2015-7744)

  - An unspecified flaw exists in the Options subcomponent
    that allows a local attacker to gain elevated
    privileges. (CVE-2016-3471)

Additionally, unspecified denial of service vulnerabilities exist in
the following MySQL subcomponents :

  - DDL (CVE-2015-4815)

  - DML (CVE-2015-4858, CVE-2015-4862, CVE-2015-4913)

  - General (CVE-2016-0605)

  - InnoDB (CVE-2015-4861)

  - Memcached (CVE-2015-4910)

  - Optimizer (CVE-2015-4800)

  - Parser (CVE-2015-4870)

  - Partition (CVE-2015-4792, CVE-2015-4802)

  - Replication (CVE-2015-4890)

  - Security:Privileges (CVE-2015-4791)

  - SP (CVE-2015-4836)");
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/2368795.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac187e77");
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/2368796.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9afc74c4");
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3089849.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42cde00c");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-27.html");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/epmos/faces/DocumentDisplay?id=2048227.1");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/rs?type=doc&id=2096144.1");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/rs?type=doc&id=2157431.1");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75a4a4fb");
  # http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da1a16c5");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?453b5f8c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.6.27 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/29");

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

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");
  script_require_ports("Host/RedHat/release", "Host/AmazonLinux/release", "Host/SuSE/release", "Host/CentOS/release");

  exit(0);
}

include("mysql_version.inc");

fix_version = "5.6.27";
exists_version = "5.6";

mysql_check_rpms(mysql_packages:default_mysql_rpm_list_server_only, fix_ver:fix_version, exists_ver:exists_version, rhel_os_list:default_mysql_rhel_os_list, centos_os_list:default_mysql_centos_os_list, suse_os_list:default_mysql_suse_os_list, ala_os_list:default_mysql_ala_os_list, severity:SECURITY_WARNING);
