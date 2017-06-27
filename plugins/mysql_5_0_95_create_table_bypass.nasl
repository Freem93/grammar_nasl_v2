#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62927);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/01/14 11:46:28 $");

  script_cve_id("CVE-2009-4030", "CVE-2012-4452");
  script_bugtraq_id(55715);
  script_osvdb_id(60665);

  script_name(english:"MySQL 5.0.95 MyISAM Table Symbolic Link Local Restriction Bypass");
  script_summary(english:"Checks version of MySQL server");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote database server is affected by a local user to bypass
privilege certain checks."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of MySQL installed may be affected by a symlink-related
restriction bypass vulnerability due to a CVE-2009-4030 regression fix
being removed in a RedHat 5.0.95 package. 

Note that this flaw has no impact if the default basedir and datadir
configuration values are unchanged."
  );
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=860808");
  script_set_attribute(
    attribute:"solution",
    value:
"Either configure MySQL to use default values for basedir and datadir
configuration variables or upgrade to MySQL version 5.1.41 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(59);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl", "os_fingerprint.nasl");
  script_require_keys("Settings/ParanoidReport", "Settings/PCI_DSS");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("mysql_func.inc");

if (!get_kb_item("Settings/PCI_DSS")) audit(AUDIT_PCI);

if (report_paranoia < 2)
{
  os = get_kb_item_or_exit("Host/OS");
  if ("linux" >!< tolower(os)) 
    exit(0, "The host does not appear to be Linux; this plugin will only run against it if 'Report paranoia' is set to 'Paranoid'.");
}

port = get_service(svc:'mysql', default:3306, exit_on_fail:TRUE);

if (mysql_init(port:port) >= 0)
{
  # Try to get variant and version
  variant = mysql_get_variant();
  version = mysql_get_version();
}
else audit(AUDIT_NOT_LISTEN, "MySQL", port);

if (!version) audit(AUDIT_SERVICE_VER_FAIL, 'MySQL', port);
if (!variant) variant = 'Unknown';

# Version 5.0.95 is vulnerable
if (version =~ '^5\\.0\\.95([^0-9]|$)')
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Variant           : ' + variant +
      '\n  Installed version : ' + version +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
} 
else audit(AUDIT_LISTEN_NOT_VULN, "MySQL", port, version); 
