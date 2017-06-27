#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73318);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/07/19 00:18:13 $");

  script_cve_id(
    "CVE-2014-2430",
    "CVE-2014-2431",
    "CVE-2014-2436",
    "CVE-2014-2440"
  );
  script_bugtraq_id(66850, 66858, 66890, 66896);
  script_osvdb_id(105905, 105912, 105916, 105917);

  script_name(english:"MySQL 5.5.x < 5.5.37 MySQL Multiple Vulnerabilities");
  script_summary(english:"Checks version of MySQL server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is potentially affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is version 5.5.x
prior to 5.5.37. It is, therefore, potentially affected by an error in
file 'client/mysql.cc' and the following components :

  - Client
  - Options
  - Performance Schema
  - RBR");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef1fc2a6");
  script_set_attribute(attribute:"see_also", value:"http://bazaar.launchpad.net/~mysql/mysql-server/5.5/revision/4601");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-37.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL 5.5.37 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/03");

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

mysql_check_version(fixed:'5.5.37', min:'5.5', severity:SECURITY_WARNING);
