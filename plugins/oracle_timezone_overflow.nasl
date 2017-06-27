#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12047);
  script_version("$Revision: 1.29 $");
  script_cvs_date("$Date: 2014/10/27 11:16:30 $");

  script_cve_id("CVE-2003-1208");
  script_bugtraq_id(9587);
  script_osvdb_id(3837, 3838, 3839, 3840);

  script_name(english:"Oracle Database 9i Multiple Functions Local Overflow");
  script_summary(english:"Checks the version of the remote database");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a buffer
overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Database, according to its version number, is
vulnerable to a buffer overflow in the query SET TIME_ZONE. An
attacker with a database account may use this flaw to gain the control
on the whole database, or even to obtain a shell on this host.");
  script_set_attribute(attribute:"see_also", value:"http://www.ngssoftware.com/advisories/ora-time-zone/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Oracle 9.2.0.3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-447");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2003/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/02/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");
  script_copyright(english:"This script is (C) 2004-2014 Tenable Network Security, Inc.");

  script_dependencie("oracle_tnslsnr_version.nasl");
  script_require_ports("Services/oracle_tnslsnr");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if ( report_paranoia < 1 ) exit(0);

port = get_kb_item_or_exit("Services/oracle_tnslsnr");

version = get_kb_item_or_exit(string("oracle_tnslsnr/",port,"/version"));
if (ereg(pattern:".*Version (9\.0\.[0-1]|9\.2\.0\.[0-2]).*", string:version))
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : 9.2.0.3' +
             '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Oracle Database", port, version);
