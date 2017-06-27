#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19416);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/05/16 14:12:51 $");

  script_cve_id("CVE-2005-2558", "CVE-2005-2573");
  script_bugtraq_id(14509);
  script_osvdb_id(18896, 18897);

  script_name(english:"MySQL < 4.0.25 / 4.1.13 / 5.0.7 Multiple Vulnerabilies");

  script_summary(english:"Checks MySQL version number");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"According to its version number, the installation of MySQL on the
remote host is potentially affected by two flaws :

  - A buffer overflow can be triggered when copying the name of a
    user-defined function into a stack-based buffer. With 
    sufficient access to create a user-defined function, an 
    attacker may be able to exploit this and execute arbitrary 
    code within the context of the affected database server
    process. (CVE-2005-2558)

  - The mysql_create_function is not fully protected against 
    directory traversal attacks. On Windows, arbitrary files can
    be included by using backslash characters. (CVE-2005-2573)");

  script_set_attribute(attribute:"see_also", value:"http://www.appsecinc.com/resources/alerts/mysql/2005-002.html");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?667d0ac2");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=112360618320729&w=2");

  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL 4.0.25 / 4.1.13 / 5.0.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  script_require_keys("Settings/ParanoidReport");

  exit(0);
}


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
  ver = mysql_get_version();

  if (
    # ??? ver =~ "^[0-3]\." ||
    # versions 4.0.x less than 4.0.25
    ver =~ "^4\.0\.([0-9]([^0-9]|$)|1[0-9]|2[0-4])" ||
    # versions 4.1.x less than 4.1.6
    ver =~ "^4\.1\.[0-5]([^0-9]|$)" ||
    # versions 5.0.x less than 5.0.7
    ver =~ "^5\.0\.[0-7]([^0-9]|$)"
  ) security_warning(port);
}
mysql_close();
