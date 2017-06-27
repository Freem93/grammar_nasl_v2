#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58661);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/01/24 21:43:59 $");
  script_cve_id(
    "CVE-2012-0882",
    "CVE-2012-1688",
    "CVE-2012-1690",
    "CVE-2012-1697",
    "CVE-2012-1703",
    "CVE-2012-2102"
  );
  script_bugtraq_id(51925, 52931, 53058, 53064, 53067, 53074);
  script_osvdb_id(78919, 81059, 81373, 81375, 81376, 81378);

  script_name(english:"MySQL 5.5 < 5.5.22 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MySQL server");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote database server is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of MySQL 5.5 installed on the remote host is earlier than
5.5.22. It is, therefore, affected by the following vulnerabilities :

  - An error exists related to the included yaSSL
    component that could allow arbitrary code execution.
    (CVE-2012-0882)

  - Errors exist related to 'Server Optimizer',
    'Server DML', 'Partition' and, in combination with
    InnoDB, 'HANDLER READ NEXT' that could allow denial of
    service attacks. (CVE-2012-1688, CVE-2012-1690,
    CVE-2012-1697, CVE-2012-1703, CVE-2012-2102)"
  );
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.5/en/news-5-5-22.html");
  # http://eromang.zataz.com/2012/04/10/oracle-mysql-innodb-bugs-13510739-and-63775-dos-demo/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?113e249d");
  script_set_attribute(attribute:"see_also", value:"http://www.openwall.com/lists/oss-security/2012/02/24/2");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to MySQL version 5.5.22 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:'5.5.22', min:'5.5', severity:SECURITY_HOLE);
