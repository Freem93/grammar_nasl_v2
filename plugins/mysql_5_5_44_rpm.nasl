#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85536);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/01/27 21:36:51 $");

  script_cve_id(
    "CVE-2015-2582",
    "CVE-2015-2620",
    "CVE-2015-2643",
    "CVE-2015-2648",
    "CVE-2015-4737",
    "CVE-2015-4752",
    "CVE-2015-4864"
  );
  script_bugtraq_id(
    75751,
    75802,
    75822,
    75830,
    75837,
    75849,
    77187
  );
  script_osvdb_id(
    124736,
    124738,
    124739,
    124741,
    124745,
    124749,
    129185
  );

  script_name(english:"Oracle MySQL 5.5.x < 5.5.44 Multiple Vulnerabilities (July 2015 CPU) (October 2015 CPU)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle MySQL installed on the remote host is 5.5.x
prior to 5.5.44. It is, therefore, affected by the following
vulnerabilities :

  - Multiple denial of service vulnerabilities exist in the
    following subcomponents which can be exploited by an
    authenticated, remote attacker :
    - DML (CVE-2015-2648)
    - GIS (CVE-2015-2582)
    - I_S (CVE-2015-4752)
    - Optimizer (CVE-2015-2643)

  - Multiple information disclosure vulnerabilities exist in
    the following subcomponents which can be exploited by an
    authenticated, remote attacker to gain access to
    sensitive information :
    - Pluggable Auth (CVE-2015-4737)
    - Security:Privileges (CVE-2015-2620)

  - An unspecified flaw exists in the Security:Privileges
    subcomponent. An authenticated, remote attacker can
    exploit this to impact integrity. (CVE-2015-4864)");
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/2368792.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?591ab328");
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/2368795.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac187e77");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-44.html");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/epmos/faces/DocumentDisplay?id=2024204.1");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/epmos/faces/DocumentDisplay?id=2048227.1");
  # http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d18c2a85");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75a4a4fb");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2015 and October
2015 Oracle Critical Patch Update advisories.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/19");

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

fix_version = "5.5.44";
exists_version = "5.5";

mysql_check_rpms(mysql_packages:default_mysql_rpm_list_server_only, fix_ver:fix_version, exists_ver:exists_version, rhel_os_list:default_mysql_rhel_os_list, centos_os_list:default_mysql_centos_os_list, suse_os_list:default_mysql_suse_os_list, ala_os_list:default_mysql_ala_os_list, severity:SECURITY_WARNING);
