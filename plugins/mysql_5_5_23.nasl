#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59967);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/02/25 02:41:51 $");

  script_cve_id("CVE-2012-1689", "CVE-2012-2750");
  script_bugtraq_id(54547, 63125);
  script_osvdb_id(83661, 83980);

  script_name(english:"MySQL 5.5 < 5.5.23 Multiple Unspecified Vulnerabilities");
  script_summary(english:"Checks version of MySQL server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple unspecified
vulnerabilities."
  );
  script_set_attribute(attribute:"description", value:
"The version of MySQL 5.5 installed on the remote host is a version
prior to 5.5.23.  As such, it is affected by two unspecified
vulnerabilities related to the 'Server Optimizer' component."
  );
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.5/en/news-5-5-23.html");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?format=multiple&id=833742");
  # http://www.oracle.com/technetwork/topics/security/cpujul2012verbose-392736.html#Oracle%20MySQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a857db8");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?532e14d2");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 5.5.23 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:'5.5.23', min:'5.5', severity:SECURITY_HOLE);
