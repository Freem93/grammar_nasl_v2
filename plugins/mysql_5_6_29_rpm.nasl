#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90831);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/06/20 20:49:18 $");

  script_cve_id(
    "CVE-2015-3194",
    "CVE-2015-3195",
    "CVE-2016-0640",
    "CVE-2016-0641",
    "CVE-2016-0644",
    "CVE-2016-0646",
    "CVE-2016-0649",
    "CVE-2016-0650",
    "CVE-2016-0661",
    "CVE-2016-0665",
    "CVE-2016-0668"
  );
  script_osvdb_id(
    131038,
    134892,
    134893,
    134894,
    134895,
    137324,
    137325,
    137326,
    137337,
    137339,
    137340,
    137342,
    137345,
    137348
  );

  script_name(english:"Oracle MySQL 5.6.x < 5.6.29 Multiple Vulnerabilities (April 2016 CPU)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle MySQL installed on the remote host is 5.6.x
prior to 5.6.29. It is, therefore, affected by the following
vulnerabilities :

  - A NULL pointer dereference flaw exists in the bundled
    version of OpenSSL in file rsa_ameth.c due to improper
    handling of ASN.1 signatures that are missing the PSS
    parameter. A remote attacker can exploit this to cause
    the signature verification routine to crash, resulting
    in a denial of service condition. (CVE-2015-3194)

  - An unspecified flaw exists in the DML subcomponent that
    allows an authenticated, remote attacker to impact
    integrity and availability. (CVE-2016-0640)

  - An unspecified flaw exists in the MyISAM subcomponent
    that allows an authenticated, remote attacker to
    disclose sensitive information or cause a denial of
    service condition. (CVE-2016-0641)

  - An unspecified flaw exists in the DDL subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0644)

  - An unspecified flaw exists in the DML subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0646)

  - An unspecified flaw exists in the PS subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0649)

  - An unspecified flaw exists in the Replication
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2016-0650)

  - An unspecified flaw exists in the Options subcomponent
    that allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0661)

  - An unspecified flaw exists in the Security: Encryption
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2016-0665)

  - An unspecified flaw exists in the InnoDB subcomponent
    that allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0668)

  - A denial of service vulnerability exists in the bundled
    OpenSSL library due to improper handling of variables
    declared as TEXT or BLOB. An authenticated, remote
    attacker can exploit this to corrupt data or cause a
    denial of service condition. (VulnDB 134892)

  - A denial of service vulnerability exists that is
    triggered when handling a 'CREATE TEMPORARY TABLE ..
    SELECT' statement involving BIT columns. An
    authenticated, remote attacker can exploit this to
    create an improper table or cause the server to exit, 
    resulting in a denial of service condition.
    (VulnDB 134893)

  - A denial of service vulnerability exists due to an
    unspecified flaw in LOCK TABLES that is triggered when
    opening a temporary MERGE table consisting of a view in
    the list of tables. An authenticated, remote attacker
    can exploit this to cause the server to exit, resulting
    in a denial of service condition. (VulnDB 134894)

  - A denial of service vulnerability exists due to a flaw
    that is triggered when repeatedly executing 'ALTER TABLE
    v1 CHECK PARTITION' as a prepared statement. An
    authenticated, remote attacker can exploit this to cause
    the server to exit, resulting in a denial of service
    condition. (VulnDB 134895)");
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/2948264.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2142a932");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-29.html");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/rs?type=doc&id=2120034.1");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?855180af");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.6.29 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/02");

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

fix_version = "5.6.29";
exists_version = "5.6";

mysql_check_rpms(mysql_packages:default_mysql_rpm_list_server_only, fix_ver:fix_version, exists_ver:exists_version, rhel_os_list:default_mysql_rhel_os_list, centos_os_list:default_mysql_centos_os_list, suse_os_list:default_mysql_suse_os_list, ala_os_list:default_mysql_ala_os_list, severity:SECURITY_WARNING);
