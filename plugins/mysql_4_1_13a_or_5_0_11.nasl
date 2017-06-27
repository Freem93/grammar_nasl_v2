#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17828);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/03/20 13:31:35 $");

  script_cve_id("CVE-2005-1849");
  script_bugtraq_id(14340);
  script_osvdb_id(18141);

  script_name(english:"MySQL < 4.1.13a / 5.0.11  Zlib Library Buffer Overflow");
  script_summary(english:"Checks version of MySQL server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is vulnerable to a denial of service
attack.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is older than
4.1.13a or 5.0.11 and as such, may have been linked with zlib 1.2.2.

On operating systems where the MySQL binaries are statically linked
(mainly Windows and HP-UX), a remote attacker could crash the server
by triggering a buffer overflow in zlib.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f319ad90");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f319ad90");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 4.1.13a / 5.0.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}


include("mysql_version.inc");

mysql_check_version(fixed:make_list('4.1.14', '5.0.11'), severity:SECURITY_WARNING);
