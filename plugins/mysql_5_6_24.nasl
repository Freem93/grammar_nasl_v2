#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82800);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/16 14:12:51 $");

  script_cve_id(
    "CVE-2015-0498",
    "CVE-2015-0499",
    "CVE-2015-0500",
    "CVE-2015-0501",
    "CVE-2015-0503",
    "CVE-2015-0505",
    "CVE-2015-0506",
    "CVE-2015-0507",
    "CVE-2015-0508",
    "CVE-2015-0511",
    "CVE-2015-2567",
    "CVE-2015-2571"
  );
  script_bugtraq_id(
    74070,
    74081,
    74086,
    74095,
    74102,
    74112,
    74115,
    74120,
    74121,
    74123,
    74130,
    74133
  );
  script_osvdb_id(
    120723,
    120725,
    120728,
    120730,
    120733,
    120734,
    120735,
    120736,
    120737,
    120739,
    120741,
    120743
  );

  script_name(english:"MySQL 5.5.x < 5.5.43 / 5.6.x < 5.6.24 Multiple DoS Vulnerabilities (April 2015 CPU)");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is version 5.5.x
prior to 5.5.43 or version 5.6.x prior to 5.6.24. It is, therefore,
potentially affected by unspecified flaws in the following MySQL
subcomponents that allow a denial of service by an authenticated,
remote attacker :

  - Replication (CVE-2015-0498)
  - Federated (CVE-2015-0499)
  - Information Schema (CVE-2015-0500)
  - Compiling (CVE-2015-0501)
  - Partition (CVE-2015-0503)
  - DDL (CVE-2015-0505)
  - InnoDB (CVE-2015-0506, CVE-2015-0508)
  - Memcached (CVE-2015-0507)
  - SP (CVE-2015-0511)
  - Security : Privileges (CVE-2015-2567)
  - Optimizer (CVE-2015-2571)");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2015-2365600.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4f2e20f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.5.43 / 5.6.24 or later as referenced in the
Oracle April 2015 Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:M/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/15");

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
mysql_check_version(fixed:make_list('5.5.43', '5.6.24'), severity:SECURITY_WARNING);
