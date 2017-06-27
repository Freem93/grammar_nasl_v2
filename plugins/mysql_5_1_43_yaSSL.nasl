#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17835);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/01/19 12:07:17 $");

  script_cve_id("CVE-2009-4484");
  script_bugtraq_id(37640, 37943, 37974);
  script_osvdb_id(61956);

  script_name(english:"MySQL < 5.0.90 / 5.1.43 / 5.5.0-m2 Multiple Buffer Overflows");
  script_summary(english:"Checks version of MySQL Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by several buffer overflow
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is older than
 5.0.90, 5.1.43 or 5.5.0-m2. Such versions use yaSSL prior to 1.9.9, 
that is vulnerable to multiple buffer overflows. These overflows allow
a remote attacker to crash the server.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?409fbf00");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d46c3ad9");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=50227");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-43.html");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.0/en/news-5-0-90.html");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8426d86b");
  script_set_attribute(attribute:"see_also", value:"http://lists.mysql.com/commits/96697");
  script_set_attribute(attribute:"see_also", value:"https://isc.sans.edu//diary.html?storyid=7900");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 5.0.90 / 5.1.43 / 5.5.0-m2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MySQL yaSSL CertDecoder::GetName Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}


include("mysql_version.inc");

mysql_check_version(fixed:make_list('5.0.90', '5.1.43', '5.5.1'), severity:SECURITY_HOLE);
