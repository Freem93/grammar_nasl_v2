#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17833);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/16 14:12:51 $");

  script_cve_id("CVE-2007-5925");
  script_bugtraq_id(26353);
  script_osvdb_id(51171);

  script_name(english:"MySQL <  5.0.54 / 5.1.23 / 6.0.4 Denial of Service");
  script_summary(english:"Checks version of MySQL server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database is vulnerable to a denial fo service attack.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is older than
5.0.54, 5.1.23 or 6.0.4. 

A remote attacker could crash the server by exploiting a flaw in
InnoDB code.");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=32125");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 5.0.54 / 5.1.23 / 6.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/11/05");
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

mysql_check_version(fixed:make_list('5.0.54', '5.1.23', '6.0.4'), severity:SECURITY_WARNING);
