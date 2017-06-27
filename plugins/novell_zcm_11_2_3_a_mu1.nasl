#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66913);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/11 21:07:50 $");

  script_cve_id(
    "CVE-2013-1093",
    "CVE-2013-1094",
    "CVE-2013-1095",
    "CVE-2013-1097"
  );
  script_bugtraq_id(60318, 60319, 60320, 60322);
  script_osvdb_id(93874, 93875, 93876, 93877);

  script_name(english:"Novell ZENworks Configuration Management < 11.2.3a Monthly Update 1 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks ZENworks version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an application that is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of Novell ZENworks Configuration
Management installed prior to 11.2.3a Monthly Update 1.  It is,
therefore, affected by the following vulnerabilities:

  - An open redirect vulnerability exists on the ZENworks
    Control Center login page due to improper validation of
    the 'fwdToURL' parameter. (CVE-2013-1093)

  - The ZENworks Control Center Login.jsp script is affected
    by a cross-site scripting vulnerability that exists due
    to improper validation on the 'language' parameter.
    (CVE-2013-1094)

  - A cross-site scripting vulnerability exists due to
    improper validation of input when handling 'onError'
    events. (CVE-2013-1095)

  - A cross-site scripting vulnerability exists due to
    improper validation of input when handling frame tag
    'onload' events. (CVE-2013-1097)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7012025");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7012499");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7012501");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7012500");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7012502");
  script_set_attribute(attribute:"solution", value:"Upgrade to Novell ZENworks 11.2.3a Monthly Update 1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/18");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:novell:zenworks_configuration_management");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("novell_zenworks_detect.nasl");
  script_require_keys("SMB/Novell/ZENworks/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

get_kb_item_or_exit("SMB/Novell/ZENworks/Installed");

app = "Novell ZENworks Configuration Management";

# Get details of the ZCM install.
path  = get_kb_item_or_exit("SMB/Novell/ZENworks/Path");
version = get_kb_item_or_exit("SMB/Novell/ZENworks/Version");
version_src = get_kb_item_or_exit("SMB/Novell/ZENworks/VersionSrc");

# These issues only affect 11.2
if (
  version =~ "^11\.2([^0-9]|$)" &&
  ver_compare(ver:version, fix:"11.2.3.24691", strict:FALSE) == -1
)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);

  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 11.2.3a Monthly Update 1 (11.2.3.24691)' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
