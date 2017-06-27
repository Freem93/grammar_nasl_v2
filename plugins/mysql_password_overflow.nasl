#
# (C) Tenable Network Security, Inc.
#

#
# Ref:
#  From: Jedi/Sector One <j@c9x.org>
#  To: bugtraq@securityfocus.com
#  Subject: Buffer overflow in MySQL
#  Message-ID: <20030910213018.GA5167@c9x.org>
#

include("compat.inc");

if (description)
{
 
 script_id(11842);  
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2016/10/05 20:44:33 $");

 script_cve_id("CVE-2003-0780");
 script_bugtraq_id(8590);
 script_osvdb_id(2537);
 script_xref(name:"RHSA", value:"2003:281-01");
 script_xref(name:"SuSE", value:"SUSE-SA:2003:042");
 
 script_name(english:"MySQL sql_acl.cc get_salt_from_password Function Password Handling Remote Overflow");
 script_summary(english:"Checks for the remote MySQL version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote database server is susceptible to a buffer overflow attack.");
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of MySQL installed on the remote
host fails to validate the length of a user-supplied password in the
'User' table in the 'get_salt_from_password()' function.  Using a
specially crafted value for a new password, an authenticated attacker
with the 'ALTER DATABASE' privilege may be able to leverage this issue
to trigger a buffer overflow and execute arbitrary code subject to the
privileges under which the database service runs.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2003/Sep/413");
 script_set_attribute(attribute:"see_also", value:"http://lists.mysql.com/announce/168");
 script_set_attribute(attribute:"see_also", value:"http://lists.mysql.com/announce/169");
 script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL 3.23.58 / 4.0.15 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/09/19");
 script_set_attribute(attribute:"vuln_publication_date", value:"2003/09/11");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
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
    version =~ "^3\.(([0-9]\..*|(1[0-9]\..*)|(2[0-2]\..*))|23\.([0-4][0-9]|5[0-7])[^0-9])"
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
