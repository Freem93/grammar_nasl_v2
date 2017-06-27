#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86657);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/28 18:52:11 $");

  script_cve_id(
    "CVE-2015-4816",
    "CVE-2015-4819",
    "CVE-2015-4879"
  );
  script_bugtraq_id(
    77134,
    77140,
    77196
  );
  script_osvdb_id(
    129164,
    129171,
    129190
  );

  script_name(english:"Oracle MySQL 5.5.x < 5.5.45 Multiple Vulnerabilities (October 2015 CPU)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle MySQL installed on the remote host is 5.5.x
prior to 5.5.45. It is, therefore, affected by the following
vulnerabilities :

  - An unspecified denial of service vulnerability exists in
    the InnoDB subcomponent which can be exploited by an
    authenticated, remote attacker. (CVE-2015-4816)

  - An unspecified flaw exists in the Client Programs
    subcomponent. A local attacker can exploit this to gain
    elevated privileges. (CVE-2015-4819)

  - An unspecified flaw exists in the DLM subcomponent.
    An authenticated, remote attacker can exploit this to
    impact confidentiality, integrity, and availability.
    (CVE-2015-4879)");
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/2368795.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac187e77");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-45.html");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/epmos/faces/DocumentDisplay?id=2048227.1");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75a4a4fb");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2015 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
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

fix_version = "5.5.45";
exists_version = "5.5";

mysql_check_rpms(mysql_packages:default_mysql_rpm_list_all, fix_ver:fix_version, exists_ver:exists_version, rhel_os_list:default_mysql_rhel_os_list, centos_os_list:default_mysql_centos_os_list, suse_os_list:default_mysql_suse_os_list, ala_os_list:default_mysql_ala_os_list, severity:SECURITY_HOLE);
