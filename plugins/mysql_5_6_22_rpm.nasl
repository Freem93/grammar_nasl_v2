#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88382);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/28 18:52:11 $");

  script_cve_id("CVE-2016-0594");
  script_osvdb_id(133172);

  script_name(english:"Oracle MySQL 5.6.x < 5.6.22 DML DoS (January 2016 CPU)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle MySQL installed on the remote host is 5.6.x
prior to 5.6.22. It is, therefore, affected by an unspecified flaw in
the DML subcomponent. An authenticated, remote attacker can exploit
this to cause a denial of service condition.");
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/2368796.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9afc74c4");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-22.html");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/rs?type=doc&id=2096144.1");
  # http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da1a16c5");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2016 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
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
  "mysql-community-common",
  "mysql-community-devel",
  "mysql-community-embedded",
  "mysql-community-libs",
  "mysql-community-libs-compat",
  "mysql-community-server",
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

fix_version = "5.6.22";
exists_version = "5.6";

mysql_check_rpms(mysql_packages:package_list, fix_ver:fix_version, exists_ver:exists_version, rhel_os_list:rhel_list, centos_os_list:centos_list, suse_os_list:suse_list, ala_os_list:ala_list, severity:SECURITY_WARNING);
