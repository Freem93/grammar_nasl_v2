#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17829);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/16 14:12:51 $");

  script_cve_id("CVE-2007-2691");
  script_bugtraq_id(24016);
  script_osvdb_id(34766);

  script_name(english:"MySQL < 4.1.23 / 5.0.42 Access Control Vulnerability");
  script_summary(english:"Checks version of MySQL server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by an access control
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is older than
4.1.23 or 5.0.42.  As such, it reportedly allows a remote,
authenticated user without the DROP privilege to rename arbitrary
tables.");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=27515");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 4.1.23 / 5.0.42 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:make_list('4.1.23', '5.0.42'), severity:SECURITY_WARNING);
