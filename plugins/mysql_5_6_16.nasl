#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73573);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/10/17 17:39:52 $");

  script_cve_id(
    "CVE-2014-0384",
    "CVE-2014-2419",
    "CVE-2014-2432",
    "CVE-2014-2434",
    "CVE-2014-2438",
    "CVE-2014-2442",
    "CVE-2014-2444",
    "CVE-2014-2450",
    "CVE-2014-2451",
    "CVE-2014-4243"
  );
  script_bugtraq_id(
    66823,
    66828,
    66835,
    66846,
    66863,
    66872,
    66875,
    66880,
    66885,
    68611
  );
  script_osvdb_id(
    105906,
    105908,
    105909,
    105910,
    105911,
    105913,
    105914,
    105915,
    105918
  );

  script_name(english:"MySQL 5.6.x < 5.6.16 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:"The remote database server is  affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is version 5.6.x
prior to 5.6.16. It is, therefore, affected by vulnerabilities in the
following components :

  - DML
  - ENFED
  - Federated
  - MyISAM
  - Optimizer
  - Partition
  - Privileges
  - Replication
  - XML");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-16.html");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef1fc2a6");
  # http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7de2f8eb");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL 5.6.16 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:'5.6.16', min:'5.6', severity:SECURITY_WARNING);
