#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(50659);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/01/24 23:01:00 $");

  script_bugtraq_id(44905);
  script_osvdb_id(69386);
  script_xref(name:"Secunia", value:"42261");

  script_name(english:"Serv-U < 10.3.0.1 SFTP Authentication Bypass");
  script_summary(english:"Checks Serv-U version");

  script_set_attribute(attribute:"synopsis", value:
"The remote SSH service is affected by an authentication bypass
vulnerability.");

  script_set_attribute(attribute:"description", value:
"According to its banner, the installed version of Serv-U is earlier
than 10.3.0.1 and is, therefore, potentially affected by the following
issue :

  - If the SFTP server has been configured to only allow
    public key authentication, it can be bypassed for
    users accounts that have no password.");

  script_set_attribute(attribute:"see_also", value:"http://www.serv-u.com/releasenotes/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Serv-U version 10.3.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:serv-u:serv-u");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_keys("Services/ssh");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


port = get_kb_item_or_exit('Services/ssh');
banner = get_kb_item_or_exit('SSH/banner/' + port);

if ('Serv-U' >!< banner)
  exit(0, 'The SSH server on port '+port+' doesn\'t look like Serv-U.');

match = eregmatch(string:banner, pattern:'Serv-U_([0-9.]+)');
if (isnull(match))
  exit(1, 'Error parsing version from banner on port '+port+'.');
else
  version = match[1];

fix = '10.3.0.1';

if (version != fix && substr_at_offset(str:fix, blob:version, offset:0))
  exit(1, 'Version '+version+' on port '+port+' isn\'t granular enough to do an accurate comparison.');

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, 'The Serv-U version '+version+' install listening on port '+port+' is not affected.');
