#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17808);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/16 14:12:51 $");

  script_cve_id("CVE-2006-4227");
  script_osvdb_id(28013);

# This is the same BID as CVE-2006-4226. It is fixed in the same 5.x versions
# but does not appear in the changelog of any 4.1.x
# 2015/11/06 BID 19559 was removed since mitre.org mistakenly linked
# it to CVE-2006-4227

  script_name(english:"MySQL < 5.0.25 / 5.1.12 Privilege Escalation");
  script_summary(english:"Checks version of MySQL Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server may allow a remote user access to objects
for which he does not have permissions.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is earlier than
5.0.25 / 5.1.12 and thus reportedly allows a remote, authenticated
user to gain privileges through a stored routine.");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.0/en/news-5-0-25.html");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=18630");
  # 4.1.x is not fixed and reached its EOL
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 5.0.25 / 5.1.12  or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/16");

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

mysql_check_version(fixed:make_list('5.0.25', '5.1.12'), severity:SECURITY_WARNING);
