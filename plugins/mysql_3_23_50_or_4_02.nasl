#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17819);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/10/05 20:44:33 $");

  script_cve_id("CVE-2002-0969");
  script_bugtraq_id(5853);
  script_osvdb_id(9908);

  script_name(english:"MySQL < 3.23.50 / 4.0.2 Local Code Execution");
  script_summary(english:"Checks version of MySQL Server");

  script_set_attribute(attribute:"synopsis", value:
"It may be possible to execute arbitrary code via the remote database
server.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is earlier than
3.23.50 or 4.0.2. 

On Win32, these versions allow a local attacker to execute arbitrary
code via a long 'datadir' parameter in the 'my.ini' file.");
  script_set_attribute(attribute:"see_also", value:"http://www.westpoint.ltd.uk/advisories/wp-02-0003.txt");
  # https://web.archive.org/web/20130828034431/http://archives.neohapsis.com/archives/vulnwatch/2002-q4/0004.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?519b15a6");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=103358628011935&w=2");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 3.23.50 / 4.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_require_ports("Services/mysql", 3306);
  script_require_keys("Settings/ParanoidReport");
  script_dependencies("mysql_version.nasl");

  exit(0);
}


include("mysql_version.inc");

mysql_check_version(fixed:make_list('3.23.50', '4.0.2'), severity:SECURITY_WARNING);
