#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72713);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/09/28 21:23:44 $");

  script_bugtraq_id(65757);
  script_osvdb_id(103684, 103685, 103687, 103690, 103691, 103692);

  script_name(english:"MariaDB 10 < 10.0.9 Multiple DoS Vulnerabilities");
  script_summary(english:"Checks MariaDB version");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB 10 running on the remote host is a version
prior to 10.0.9. It is, therefore, potentially affected by denial of
service vulnerabilities due to errors related to the following :

  - Union queries
  - Prepare queries
  - Join::prepare queries
  - ONLY_FULL_GROUP_BY queries
  - NAME_CONST queries");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-5505");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-5581");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-5617");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-5655");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.atlassian.net/browse/MDEV-714");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.0.9 or later. Alternatively, apply the
vendor-supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(variant:'MariaDB', fixed:'10.0.9-MariaDB', min:'10.0', severity:SECURITY_WARNING);
