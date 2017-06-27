#
# (C) Tenable Network Security, Inc.
#

include("audit.inc");
include("compat.inc");

if (description)
{
  script_id(83347);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/07 18:00:12 $");

  script_cve_id("CVE-2015-3152");
  script_bugtraq_id(74398);
  script_osvdb_id(121459);

  script_name(english:"MySQL 5.1.x < 5.7.3 SSL/TLS Downgrade MitM (BACKRONYM)");
  script_summary(english:"Checks the version of the MySQL 5.x client libraries.");

  script_set_attribute(attribute:"synopsis", value:
"The remote MySQL client library is affected by a security feature
bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of the MySQL client library installed
that is 5.1.x, 5.5.x, 5.6.x, or 5.7.x prior to 5.7.3. It is,
therefore, affected by a security feature bypass vulnerability known
as 'BACKRONYM' due to a failure to properly enforce the requirement of
an SSL/TLS connection when the --ssl client option is used. A
man-in-the-middle attacker can exploit this flaw to coerce the client
to downgrade to an unencrypted connection, allowing the attacker to
disclose data from the database or manipulate database queries.");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-3.html");
  script_set_attribute(attribute:"see_also", value:"http://backronym.fail/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.7.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  script_require_keys("Settings/ParanoidReport");

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:make_list('5.7.3'), min:'5.1', severity:SECURITY_WARNING);
