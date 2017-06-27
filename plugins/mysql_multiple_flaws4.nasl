#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(17313);  
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2016/10/05 20:44:33 $");

 script_cve_id("CVE-2005-0709", "CVE-2005-0710", "CVE-2005-0711");
 script_bugtraq_id(12781);
 script_osvdb_id(14676, 14677, 14678);
 
 script_name(english:"MySQL < 4.0.24 / 4.1.10a Multiple Vulnerabilities");
 script_summary(english:"Checks for the remote MySQL version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of MySQL which older than version
4.0.24 or 4.1.10a.  Such versions are potentially affected by multiple
issues.
 
  - MySQL uses predictable file names when creating 
    temporary tables, which allows local users with 'CREATE
    TEMPORARY TABLE' privileges to overwrite arbitrary files
    via a symlink attack. (CVE-2005-0711)

  - A flaw exists that may allow a malicious user to gain
    access to unauthorized privileges when an authenticated
    user with 'INSERT' and 'DELETE' privileges bypasses 
    library path restrictions using 'INSERT INTO' to modify
    the 'mysql.func' table. (CVE-2005-0709)

  - A flaw exists that may allow a mlicious user to load
    arbitrary libraries when an authenticated user with 
    'INSERT' and 'DELETE' privileges use the 'CREATE 
    FUNCTION' command to specify and load an arbitrary
    custom library. (CVE-2005-0710)");
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/TA23465?viewlocale=en_US");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/vulnwatch/2005/q1/81");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/vulnwatch/2005/q1/82");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/vulnwatch/2005/q1/83");
 script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL 4.0.24, 4.1.10a, or later as this reportedly fixes 
the issue.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/11");
 script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/11");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
    version =~ "^([0-3]\.|4\.0\.([0-9]|1[0-9]|2[0-3])([^0-9]|$)|4\.1\.[0-9][^0-9])"
  )
  {
    if (report_verbosity > 0)
    {
      report = '\nThe remote MySQL server\'s version is :\n\n  '+version+'\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}
mysql_close();
