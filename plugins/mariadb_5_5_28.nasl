#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65731);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/09/28 21:23:45 $");

  script_cve_id(
    "CVE-2012-0553",
    "CVE-2012-3160",
    "CVE-2012-3177",
    "CVE-2012-3180",
    "CVE-2012-5060"
  );
  script_bugtraq_id(56003, 56005, 56027, 57411, 58594);
  script_osvdb_id(86262, 86268, 86273, 89250, 91536);

  script_name(english:"MariaDB 5.5 < 5.5.28 Multiple Vulnerabilities");
  script_summary(english:"Checks MariaDB version");

  script_set_attribute(attribute:"synopsis", value:"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB 5.5 running on the remote host is prior to
5.5.28. It is, therefore, potentially affected by vulnerabilities in
the following components :

  - GIS Extension
  - Server
  - Server Installation
  - Server Optimizer
  - yaSSL");
  script_set_attribute(attribute:"see_also", value:"https://kb.askmonty.org/en/mariadb-5528-release-notes/");
  # MariaDB 5.5.28 includes MySQL 5.5.28
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.5/en/news-5-5-28.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to MariaDB version 5.5.28 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(variant:'MariaDB', fixed:'5.5.28-MariaDB', min:'5.5', severity:SECURITY_HOLE);
