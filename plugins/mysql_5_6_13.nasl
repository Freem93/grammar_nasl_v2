#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70463);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/02/25 02:41:51 $");

  script_cve_id(
    "CVE-2013-3839",
    "CVE-2013-5767",
    "CVE-2013-5786",
    "CVE-2013-5793",
    "CVE-2013-5807"
  );
  script_bugtraq_id(63105, 63107, 63109, 63113, 63116);
  script_osvdb_id(98508, 98509, 98510, 98511, 98512);

  script_name(english:"MySQL 5.6.x < 5.6.13 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MySQL server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server may be affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is 5.6.x older than
5.6.13.  As such, it is reportedly affected by vulnerabilities in the
following components :

  - InnoDB
  - Server Optimizer
  - Server Replication");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-13.html");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?532e14d2");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 5.6.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
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

mysql_check_version(fixed:'5.6.13', severity:SECURITY_WARNING, min:'5.6');
