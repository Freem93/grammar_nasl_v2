#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86547);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/04/24 04:42:09 $");

  script_cve_id(
    "CVE-2015-1793",
    "CVE-2015-4730",
    "CVE-2015-4766",
    "CVE-2015-4791",
    "CVE-2015-4792",
    "CVE-2015-4800",
    "CVE-2015-4802",
    "CVE-2015-4807",
    "CVE-2015-4815",
    "CVE-2015-4819",
    "CVE-2015-4826",
    "CVE-2015-4830",
    "CVE-2015-4833",
    "CVE-2015-4836",
    "CVE-2015-4858",
    "CVE-2015-4861",
    "CVE-2015-4862",
    "CVE-2015-4864",
    "CVE-2015-4866",
    "CVE-2015-4870",
    "CVE-2015-4879",
    "CVE-2015-4890",
    "CVE-2015-4895",
    "CVE-2015-4904",
    "CVE-2015-4905",
    "CVE-2015-4910",
    "CVE-2015-4913",
    "CVE-2015-7744",
    "CVE-2016-0605"
  );
  script_osvdb_id(
    124300,
    124947,
    129164,
    129165,
    129166,
    129167,
    129169,
    129170,
    129172,
    129173,
    129174,
    129175,
    129176,
    129177,
    129178,
    129179,
    129180,
    129181,
    129182,
    129183,
    129184,
    129185,
    129186,
    129187,
    129188,
    129189,
    129190,
    133188,
    133189
  );

  script_name(english:"MySQL 5.6.x < 5.6.27 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.6.x prior to
5.6.27. It is, therefore, potentially affected by the following
vulnerabilities :

  - A certificate validation bypass vulnerability exists in
    the Security:Encryption subcomponent due to a flaw in
    the X509_verify_cert() function in x509_vfy.c that is
    triggered when locating alternate certificate chains
    when the first attempt to build such a chain fails. A
    remote attacker can exploit this, by using a valid leaf
    certificate as a certificate authority (CA), to issue
    invalid certificates that will bypass authentication.
    (CVE-2015-1793)

  - An unspecified flaw exists in the Client Programs
    subcomponent. A local attacker can exploit this to gain
    elevated privileges. (CVE-2015-4819)

  - An unspecified flaw exists in the Types subcomponent.
    An authenticated, remote attacker can exploit this to
    gain access to sensitive information. (CVE-2015-4826)

  - An unspecified flaws exist in the Security:Privileges
    subcomponent. An authenticated, remote attacker can
    exploit these to impact integrity. (CVE-2015-4830,
    CVE-2015-4864)

  - An unspecified flaw exists in the DLM subcomponent.
    An authenticated, remote attacker can exploit this to
    impact integrity. (CVE-2015-4879)

  - An unspecified flaw exists in the Server Security
    Encryption subcomponent that allows an authenticated,
    remote attacker to disclose sensitive information.
    (CVE-2015-7744)

Additionally, unspecified denial of service vulnerabilities can also
exist in the following MySQL subcomponents :

  - DDL (CVE-2015-4815)

  - DML (CVE-2015-4858, CVE-2015-4862, CVE-2015-4905,
    CVE-2015-4913)

  - InnoDB (CVE-2015-4861, CVE-2015-4866, CVE-2015-4895)

  - libmysqld (CVE-2015-4904)

  - Memcached (CVE-2015-4910)

  - Optimizer (CVE-2015-4800)

  - Parser (CVE-2015-4870)

  - Partition (CVE-2015-4792, CVE-2015-4802, CVE-2015-4833)

  - Query (CVE-2015-4807)

  - Replication (CVE-2015-4890)

  - Security : Firewall (CVE-2015-4766)

  - Server : General (CVE-2016-0605)

  - Security : Privileges (CVE-2015-4791)

  - SP (CVE-2015-4836)

  - Types (CVE-2015-4730)");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-27.html");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75a4a4fb");
  # http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?66027465");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.6.27 or later as referenced in the October
2015 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:'5.6.27', min:'5.6', severity:SECURITY_HOLE);
