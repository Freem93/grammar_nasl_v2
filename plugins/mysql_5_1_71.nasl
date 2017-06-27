#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70461);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/02/25 02:41:51 $");

  script_cve_id("CVE-2012-2750", "CVE-2013-3839");
  script_bugtraq_id(63109, 63125);
  script_osvdb_id(83661, 98508);

  script_name(english:"MySQL 5.1 < 5.1.71 Server Optimizer Denial of Service");
  script_summary(english:"Checks version of MySQL server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server may be affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL 5.1 installed on the remote host is earlier than
5.1.71.  It is, therefore, potentially affected by multiple denial of
service vulnerabilities in the 'Server Optimizer' component. 

Note: Oracle has provided a workaround to address the issue for
CVE-2012-2750.");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?532e14d2");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/relnotes/mysql/5.1/en/news-5-1-71.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 5.1.71 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:'5.1.71', min:'5.1', severity:SECURITY_HOLE);
