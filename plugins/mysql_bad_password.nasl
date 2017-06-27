#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if (description)
{
  script_id(10343);
  script_version("$Revision: 1.28 $");
  script_cvs_date("$Date: 2016/11/28 21:52:57 $");

  script_cve_id("CVE-2000-0148");
  script_bugtraq_id(975);
  script_osvdb_id(261);

  script_name(english:"MySQL Short Check String Authentication Bypass");
  script_summary(english:"Checks for the remote MySQL version");

  script_set_attribute(
    attribute:'synopsis',
    value:"The remote MySQL server is vulnerable to an access control breach."
  );

  script_set_attribute(
    attribute:'description',
    value:
"The remote version of MySQL is older than (or as old as) version
3.22.30 or 3.23.10.  Thus, it may allow attacker who knows a valid
username to access database tables without a valid password."
  );

  script_set_attribute(
    attribute:'solution',
    value:
"Upgrade to a newer version, or edit the file
mysql-xxx/sql/password.c, and search for the 'while(*scrambled)' loop. 
In front of it, add :

  'if(strlen(scrambled) != strlen(to))return 1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(
    attribute:'see_also',
    value:"http://seclists.org/bugtraq/2000/Feb/134"
  );

  script_set_attribute(attribute:"plugin_publication_date", value:"2000/03/08");
  script_set_attribute(attribute:"vuln_publication_date", value:"2000/02/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
  script_family(english:"Databases");

  script_dependencie("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  script_require_keys("Settings/ParanoidReport");

  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("mysql_func.inc");


# nb: banner checks of open source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2)
  exit(1, "This plugin only runs if 'Report paranoia' is set to 'Paranoid'.");

port = get_service(svc:"mysql", default:3306, exit_on_fail:TRUE);

if (mysql_init(port:port, exit_on_fail:TRUE) == 1)
{
  version = mysql_get_version();

  if (
    strlen(version) &&
    version =~ "^3\.(22\.(2[6789]|30)|23\.([89]|10))"
  )
  {
    if (report_verbosity > 0)
    {
      report = '\nThe remote MySQL server\'s version is :\n\n  '+version+'\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
}
mysql_close();

