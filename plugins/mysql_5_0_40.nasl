#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17832);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/20 14:12:06 $");

  script_cve_id("CVE-2007-2583", "CVE-2007-2692");
  script_bugtraq_id(23911, 24011);
  script_osvdb_id(34734, 34765);
  script_xref(name:"EDB-ID", value:"30020");

  script_name(english:"MySQL 5.0 < 5.0.40 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MySQL server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is reportedly 
affected by several issues :

  - Evaluation of an 'IN()' predicate with a decimal-valued
    argument causes a service crash.

  - A remote, authenticated user can gain privileges.");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=27337");
  script_set_attribute(attribute:"see_also", value:"http://lists.mysql.com/commits/23685");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=27513");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 5.0.40 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/10");
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

mysql_check_version(fixed:'5.0.40', severity:SECURITY_WARNING, min:'5.0');
