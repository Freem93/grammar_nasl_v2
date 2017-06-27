#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17822);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/10/05 20:44:33 $");

  script_cve_id("CVE-2003-1331");
  script_bugtraq_id(7887);
  script_osvdb_id(60356);

  script_name(english:"MySQL < 4.0.14 libmysqlclient Buffer Overflow");
  script_summary(english:"Checks version of MySQL Server");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code could be executed by the database client library on
the remote host.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is older than 4.0.14.

The client library (libmysqlclient) is thus reportedly affected by a
buffer overflow.  A local attacker could execute arbitrary code
through a long socket name. 

Note that RedHat does not consider that this flaw is a security
issue.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2003/Jun/371");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 4.0.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/06/01");
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

mysql_check_version(fixed:'4.0.14', severity:SECURITY_WARNING);
