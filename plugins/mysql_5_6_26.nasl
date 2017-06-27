#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85223);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/06/20 20:49:18 $");

  script_osvdb_id(125441, 125442, 125443, 125444);

  script_name(english:"MySQL 5.5.x < 5.5.45 / 5.6.x < 5.6.26 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.5.x prior to
5.5.45 or 5.6.x prior to 5.6.26. It is, therefore, potentially
affected by the following vulnerabilities :

  - A buffer overflow condition exists in mysqlslap due to
    improper validation of user-supplied input when parsing
    options. An attacker can exploit this to cause a denial
    of service or possibly execute arbitrary code.
    (VulnDB 125441)

  - A flaw exists when handling CHAR(0) NOT NULL column
    operations. An attacker can exploit this to cause the
    server to exit, resulting in a denial of service.
    (VulnDB 125442)

  - A use-after-free error exists whenever the Enterprise
    Firewall and Binary Logging components are both enabled.
    An attacker can exploit this to execute arbitrary code.
    (VulnDB 125443)

  - An off-by-one overflow exists due to improper validation
    of user-supplied input by the functions related to
    string copying. An attacker can exploit this to cause
    a denial of service or possibly execute arbitrary code.
    (VulnDB 125444)");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-45.html");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-26.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.5.45 / 5.6.26 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");

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

mysql_check_version(fixed:make_list('5.5.45', '5.6.26'), severity:SECURITY_HOLE);
