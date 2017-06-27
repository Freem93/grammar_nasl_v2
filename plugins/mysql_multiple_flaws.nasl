#
# (C) Tenable Network Security, Inc.
#

# Ref: 
# From: Stefan Esser <s.esser@e-matters.de>
# Message-ID: <20021212112625.GA431@php.net>
# To: full-disclosure@lists.netsys.com
# Cc: vulnwatch@vulnwatch.org, bugtraq@securityfocus.com
# Subject: [VulnWatch] Advisory 04/2002: Multiple MySQL vulnerabilities
#
# URL:
# http://security.e-matters.de/advisories/042002.html 
#

include("compat.inc");

if (description)
{
 
 script_id(11192);  
 script_version("$Revision: 1.31 $");
 script_cvs_date("$Date: 2014/05/09 20:04:42 $");

 script_cve_id("CVE-2002-1373", "CVE-2002-1374", "CVE-2002-1375", "CVE-2002-1376");
 script_bugtraq_id(6368, 6370, 6373, 6374, 6375, 8796);
 script_osvdb_id(8885, 8886, 8887, 8888, 8889);
 script_xref(name:"RHSA", value:"2002:166");
 script_xref(name:"RHSA", value:"2002:288");
 script_xref(name:"RHSA", value:"2002:289");
 script_xref(name:"SuSE", value:"SUSE-SA");
 
 script_name(english:"MySQL < 3.23.54 / 4.0.6 Multiple Vulnerabilities");
 script_summary(english:"Checks for the remote MySQL version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote database server could be disabled remotely.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of MySQL older than 3.23.54 or
4.0.6. 

The remote version of this product contains several flaw that could
allow an attacker to crash this service remotely.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e1b5afc");
 script_set_attribute(attribute:"solution", value:
"Upgrade MySQL to version 3.23.54 or 4.0.6.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/12/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/12/12");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2014 Tenable Network Security, Inc.");
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
    version =~ "^3\.(([0-9]\..*|(1[0-9]\..*)|(2[0-2]\..*))|23\.([0-4][0-9]|5[0-3])[^0-9])"
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
