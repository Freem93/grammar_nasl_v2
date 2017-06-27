#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10626);
 script_version("$Revision: 1.34 $");
 script_cvs_date("$Date: 2016/11/28 21:52:57 $");

 script_cve_id("CVE-2000-0045", "CVE-2001-1275", "CVE-2001-0407");
 script_bugtraq_id(2380, 2522, 926);
 script_osvdb_id(520, 8979, 9906);

 script_name(english:"MySQL < 3.23.36 Multiple Vulnerabilities");
 script_summary(english:"Checks for the remote MySQL version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The installed version of MySQL is older than version 3.23.36. 
Such versions are potentially affected by multiple vulnerabilities :  

  - It is possible to modify arbitrary files and gain
    privileges by creating a database with '..' characters.
    (CVE-2001-0407)

  - Users with a MySQL account can use the 'SHOW GRANTS'
    command to obtain the encrypted administrator password
    from the 'mysql.user' table. (CVE-2001-1275)

  - Local users can modify passwords for arbitrary MySQL
    users via the 'GRANT' privilege. (CVE-2000-0045)");
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=98089552030459&w=2");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Jan/129");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Mar/429");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Mar/269");
 script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 3.23.36 or later as this reportedly fixes the
issue.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2001/03/08");
 script_set_attribute(attribute:"vuln_publication_date", value:"2000/01/11");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
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
    version =~ "^3\.(([0-9]\..*)|(1[0-9]\..*)|(2(([0-2]\..*)|3\.(([0-9]$)|([0-2][0-9])|(3[0-5])))))"
  )
  {
    if (report_verbosity > 0)
    {
      report =
        '\nThe remote MySQL server\'s version is :\n'+
        '  '+version+'\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
}
mysql_close();

