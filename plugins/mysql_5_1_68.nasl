#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65733);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/11/26 12:27:35 $");

  script_cve_id("CVE-2012-0553", "CVE-2013-1492");
  script_bugtraq_id(58594, 58595);
  script_osvdb_id(91534, 91536);

  script_name(english:"MySQL 5.1 < 5.1.68 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MySQL server");

  script_set_attribute(attribute:"synopsis", value:"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(
    attribute:"description",
    value:
"The version of MySQL 5.1 installed on the remote host is earlier than
5.1.68 and is, therefore, affected by vulnerabilities related to
'yaSSL'.  These errors could result in buffer overflows and possibly
arbitrary code execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-251/");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-68.html");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/relnotes/mysql/5.1/en/news-5-1-68.html");
  script_set_attribute(attribute:"see_also", value:"https://blogs.oracle.com/sunsecurity/entry/cve_2012_0553_buffer_overflow");
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html#MySQL5.6");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef866628");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 5.1.68 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:'5.1.68', min:'5.1', severity:SECURITY_HOLE);
