#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59448);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/20 14:12:06 $");

  script_cve_id(
    "CVE-2012-0540",
    "CVE-2012-1689",
    "CVE-2012-1734",
    "CVE-2012-2122",
    "CVE-2012-2749"
  );
  script_bugtraq_id(53911, 54540, 54551, 54547, 55120);
  script_osvdb_id(82803, 82804, 83976, 83979, 83980, 84755);
  script_xref(name:"EDB-ID", value:"19092");
  
  script_name(english:"MySQL 5.1 < 5.1.63 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MySQL server");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote database server is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of MySQL 5.1 installed on the remote host is earlier than
5.1.63 and is, therefore, affected by multiple vulnerabilities :

  - Several errors exist related to 'GIS Extension' and
    'Server Optimizer' components that can allow denial of
    service attacks. (CVE-2012-0540, CVE-2012-1689,
    CVE-2012-1734)

  - A security bypass vulnerability exists that occurs due
    to improper casting during user login sessions.
    (Bug #64884 / CVE-2012-2122)

  - An error exists related to key length and sort order
    index that can lead to application crashes.
    (Bug #59387 / CVE-2012-2749)"
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2012/q2/493");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-63.html");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a857db8");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 5.1.63 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/11");

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

mysql_check_version(fixed:'5.1.63', min:'5.1', severity:SECURITY_HOLE);
