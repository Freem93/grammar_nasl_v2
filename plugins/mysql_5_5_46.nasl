#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86546);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/04/28 18:52:11 $");

  script_cve_id(
    "CVE-2015-4792",
    "CVE-2015-4802",
    "CVE-2015-4807",
    "CVE-2015-4815",
    "CVE-2015-4816",
    "CVE-2015-4819",
    "CVE-2015-4826",
    "CVE-2015-4830",
    "CVE-2015-4836",
    "CVE-2015-4858",
    "CVE-2015-4861",
    "CVE-2015-4864",
    "CVE-2015-4870",
    "CVE-2015-4879",
    "CVE-2015-4913",
    "CVE-2015-7744"
    );
  script_osvdb_id(
    129164,
    129165,
    129167,
    129171,
    129173,
    129174,
    129176,
    129177,
    129179,
    129181,
    129182,
    129185,
    129186,
    129189,
    129190,
    133188
  );

  script_name(english:"MySQL 5.5.x < 5.5.46 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.5.x prior to
5.5.46. It is, therefore, affected by the following vulnerabilities :

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

  - DML (CVE-2015-4858, CVE-2015-4913) 

  - InnoDB (CVE-2015-4816, CVE-2015-4861)

  - Parser (CVE-2015-4870)

  - Partition (CVE-2015-4792, CVE-2015-4802)

  - Query (CVE-2015-4807)

  - SP (CVE-2015-4836)");
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/2368795.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac187e77");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-46.html");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75a4a4fb");
  # http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?66027465");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.5.46 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/20");
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
mysql_check_version(fixed:'5.5.46', min:'5.5', severity:SECURITY_HOLE);
