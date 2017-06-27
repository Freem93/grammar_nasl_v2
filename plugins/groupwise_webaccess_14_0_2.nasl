#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85182);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/08/04 14:00:09 $");

  script_cve_id("CVE-2014-0611");
  script_bugtraq_id(76008);
  script_osvdb_id(124990);

  script_name(english:"Novell GroupWise WebAccess 12.0.x < 12.0.4 / 14.0.x < 14.0.2 Multiple XSS Vulnerabilities");
  script_summary(english:"Checks the version of GroupWise WebAccess.");

  script_set_attribute(attribute:"synopsis",value:
"The application installed on the remote host is affected by multiple
cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Novell GroupWise WebAccess installed on the remote
host is affected by multiple unspecified cross-site scripting (XSS)
vulnerabilities that can allow a remote attacker to trick
authenticated users into executing arbitrary JavaScript code in the
context of the WebAccess session.");
  script_set_attribute(attribute:"see_also",value:"https://www.novell.com/support/kb/doc.php?id=7016653");
  script_set_attribute(attribute:"solution",value:
"Upgrade to Novell WebAccess 2014 SP2 or WebAccess 2012 SP4.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/07/06");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/03");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:novell:groupwise_webaccess");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("groupwise_webaccess_detect.nasl");
  script_require_keys("SMB/GroupWise WebAccess/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/GroupWise WebAccess/Version");
path = get_kb_item_or_exit("SMB/GroupWise WebAccess/Path");

fixed_version = NULL;

if (version =~ '^12\\.' && ver_compare(ver:version, fix:"12.0.4") == -1)
  fixed_version = "12.0.4";
else if (version =~ '^14\\.' && ver_compare(ver:version, fix:"14.0.2") == -1)
  fixed_version = "14.0.2";

if(!isnull(fixed_version))
{
  set_kb_item(name:"www/0/XSS", value:TRUE);

  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
audit(AUDIT_INST_PATH_NOT_VULN, 'GroupWise WebAccess', version, path);
