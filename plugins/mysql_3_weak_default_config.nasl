#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17821);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/10/05 20:44:33 $");

  script_cve_id(
    "CVE-2002-1809",
    "CVE-2002-1921",
    "CVE-2002-1923"
  );
  script_bugtraq_id(
    5503,
    5511,
    5513
  );
  script_osvdb_id(
    380,
    59906,
    59907
  );

  script_name(english:"MySQL 3.20.32 - 3.23.52 Weak Default Configuration");
  script_summary(english:"Checks the version of MySQL Server.");

  script_set_attribute(attribute:"synopsis", value:
"The default configuration of the remote database server may be
weak.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is 3.20.32 to
3.23.52. On Windows, the default configuration used in these versions
is weak :

  - The database server binds to all network interfaces and 
    can be reached from outside. (CVE-2002-1921)

  - Logging is disabled, attackers will not be detected. 
    (CVE-2002-1923)

  - root's password is blank. (CVE-2002-1809)");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Aug/281");
  script_set_attribute(attribute:"solution", value:
"Edit the configuration file and add this line if needed :

bind-address=127.0.0.1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl", "os_fingerprint.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:'3.23.53', min: '3.20.32', severity:SECURITY_HOLE);
