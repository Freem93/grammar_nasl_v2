#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85539);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/20 14:12:06 $");

  script_cve_id(
    "CVE-2015-2582",
    "CVE-2015-2611",
    "CVE-2015-2617",
    "CVE-2015-2639",
    "CVE-2015-2641",
    "CVE-2015-2643",
    "CVE-2015-2648",
    "CVE-2015-2661",
    "CVE-2015-4752",
    "CVE-2015-4761",
    "CVE-2015-4767",
    "CVE-2015-4769",
    "CVE-2015-4771",
    "CVE-2015-4772",
    "CVE-2015-4864"
  );
  script_bugtraq_id(
    75751,
    75753,
    75760,
    75762,
    75770,
    75774,
    75781,
    75813,
    75815,
    75822,
    75830,
    75835,
    75844,
    75849,
    77187
  );
  script_osvdb_id(
    124735,
    124736,
    124737,
    124738,
    124739,
    124741,
    124742,
    124743,
    124746,
    124747,
    124748,
    124750,
    124751,
    124752,
    129185
  );

  script_name(english:"Oracle MySQL 5.6.x < 5.6.25 Multiple Vulnerabilities (July 2015 CPU) (October 2015 CPU)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle MySQL installed on the remote host is 5.6.x
prior to 5.6.25. It is, therefore, affected by the following
vulnerabilities :

  - Multiple denial of service vulnerabilities exist in the
    following subcomponents which can be exploited by a
    remote, authenticated attacker :
    - Partition (CVE-2015-2617)
    - DML (CVE-2015-2648, CVE-2015-2611)
    - GIS (CVE-2015-2582)
    - I_S (CVE-2015-4752)
    - Optimizer (CVE-2015-2643)
    - Partition (CVE-2015-4772)
    - Memcached (CVE-2015-4761)
    - RBR (CVE-2015-4771)
    - Security:Firewall (CVE-2015-4769, CVE-2015-4767)
    - Security:Privileges (CVE-2015-2641)

  - An unspecified vulnerability exists related to the
    Security:Firewall subcomponent that can be exploited by
    an authenticated, remote attacker to have an impact on
    the integrity of the system. (CVE-2015-2639)

  - A denial of service vulnerability exists in the Client
    subcomponent which can be exploited by a local attacker.
    (CVE-2015-2661)

  - An unspecified flaw exists in the Security:Privileges
    subcomponent. An authenticated, remote attacker can
    exploit this to impact integrity. (CVE-2015-4864)");
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/2368792.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?591ab328");
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/2368795.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac187e77");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-25.html");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/epmos/faces/DocumentDisplay?id=2024204.1");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/epmos/faces/DocumentDisplay?id=2048227.1");
  # http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d18c2a85");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75a4a4fb");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2015 and October
2015 Oracle Critical Patch Update advisories.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"Databases");

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
  "SUSE13.2"
);
centos_list = make_list(
  "CentOS-5",
  "CentOS-6",
  "CentOS-7"
);

fix_version = "5.6.25";
exists_version = "5.6";

mysql_check_rpms(mysql_packages:package_list, fix_ver:fix_version, exists_ver:exists_version, rhel_os_list:rhel_list, centos_os_list:centos_list, suse_os_list:suse_list, ala_os_list:ala_list, severity:SECURITY_WARNING);
