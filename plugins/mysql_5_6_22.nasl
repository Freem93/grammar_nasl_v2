#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80886);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/04/24 04:42:09 $");

  script_cve_id(
    "CVE-2014-6568",
    "CVE-2015-0374",
    "CVE-2015-0381",
    "CVE-2015-0382",
    "CVE-2015-0385",
    "CVE-2015-0409",
    "CVE-2015-0411",
    "CVE-2015-0432",
    "CVE-2016-0594"
  );
  script_bugtraq_id(
    72191,
    72200,
    72210,
    72214,
    72217,
    72223,
    72227,
    72229
  );
  script_osvdb_id(
    117329,
    117331,
    117332,
    117333,
    117334,
    117335,
    117336,
    117337,
    133172
  );

  script_name(english:"MySQL 5.5.x < 5.5.41 / 5.6.x < 5.6.22 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is version 5.5.x
prior to 5.5.41 or 5.6.x prior to 5.6.22. It is, therefore, affected
by vulnerabilities in the following components :

  - Server : DDL
  - Server : InnoDB : DDL : Foreign Key
  - Server : InnoDB : DML
  - Server : Optimizer
  - Server : Pluggable Auth
  - Server : Replication
  - Server : Security : Encryption
  - Server : Security : Privileges : Foreign Key");
  # http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?019fc4c0");
  # http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?66027465");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.5.41 / 5.6.22 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/21");

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
mysql_check_version(fixed:make_list('5.5.41', '5.6.22'), severity:SECURITY_HOLE);
