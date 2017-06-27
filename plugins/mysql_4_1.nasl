#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17824);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/06/23 19:16:51 $");

  script_bugtraq_id(7500);
  script_cve_id("CVE-2003-1480");
  script_osvdb_id(59616);

  script_name(english:"MySQL Weak Hash Algorithm");
  script_summary(english:"Checks version of MySQL Server");

  script_set_attribute(attribute:"synopsis", value:
"Passwords could be brute-forced on the remote database server.");

  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is older than
4.1.1.  As such, it reportedly uses a weak algorithm to hash the
passwords.  A attacker who can read the mysql.user table will be able
to retrieve the plaintext passwords quickly by brute-force attack.");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.0/en/application-password-use.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 4.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}


include("mysql_version.inc");

mysql_check_version(fixed:'4.1.1', severity:SECURITY_WARNING);
