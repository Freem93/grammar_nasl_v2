#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84798);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/28 21:23:45 $");

  script_osvdb_id(124021);

  script_name(english:"MariaDB 5.5.43 < 5.5.44 'ADD INDEX' Statement DoS");
  script_summary(english:"Checks the MariaDB version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running on the remote host is 5.5.43 prior to
5.5.44. It is, therefore, affected by a denial of service
vulnerability due to an unspecified flaw that exists in file
sql_parse.cc. A remote, authenticated attacker can exploit this, via a
crafted ADD INDEX statement, to crash the database.");
  script_set_attribute(attribute:"see_also", value:"https://blog.mariadb.org/mariadb-5-5-44-now-available/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-8166");
  script_set_attribute(attribute:"solution", value:"Upgrade to MariaDB version 5.5.44 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/16");
  
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
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

mysql_check_version(variant:'MariaDB', fixed:'5.5.44-MariaDB', min:'5.5.43', severity:SECURITY_WARNING);
