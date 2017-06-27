#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71974);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/04/20 04:29:52 $");

  script_cve_id(
    "CVE-2013-5908",
    "CVE-2014-0401",
    "CVE-2014-0412",
    "CVE-2014-0420",
    "CVE-2014-0437"
  );
  script_bugtraq_id(64849, 64880, 64888, 64896, 64898);
  script_osvdb_id(102067, 102071, 102074, 102077, 102078);

  script_name(english:"MySQL 5.5.x < 5.5.35 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MySQL server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server may be affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is version 5.5.x
prior to 5.5.35.  It is, therefore, potentially affected by
vulnerabilities in the following components :

  - Error Handling
  - InnoDB
  - Privileges
  - Optimizer
  - Replication");
  # http://www.oracle.com/technetwork/topics/security/cpujan2014-1972949.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e038a357");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-35.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL 5.5.35 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/15");

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

mysql_check_version(fixed:'5.5.35', min:'5.5', severity:SECURITY_WARNING);
