#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53829);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/15 13:39:08 $");

  script_cve_id("CVE-2011-0286");
  script_bugtraq_id(47324);
  script_osvdb_id(73427);

  script_name(english:"BlackBerry Enterprise Server Web Desktop Manager XSS (KB26296)");
  script_summary(english:"Checks version and looks for workaround.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of BlackBerry Enterprise Server on the remote host
reportedly contains a cross-site scripting vulnerability in its Web
Desktop Manager component. An attacker may be able to leverage this
issue to execute arbitrary script code in the browser of an
authenticated user in the context of the affected site and to steal
cookie-based authentication credentials.");
  script_set_attribute(attribute:"see_also", value:"http://www.blackberry.com/btsc/KB26296");
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/fulldisclosure/2011/Apr/224"
  );
  script_set_attribute(attribute:"solution", value:
"Install Service Pack 1 or 2 Interim Security Software Update for April
12th 2011, or upgrade to 5.0.2 MR5 or 5.0.3 MR1 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/06");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:rim:blackberry_enterprise_server");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("blackberry_es_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");

function md5_file(path)
{
  local_var blob, fh, len, md5;

  md5 = NULL;
  fh = CreateFile(
    file:path,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    len = GetFileSize(handle:fh);
    if (len)
    {
      blob = ReadFile(handle:fh, length:len, offset:0);
      md5 = hexstr(MD5(blob));
    }
    CloseFile(handle:fh);
  }

  return md5;
}

# Skip versions that aren't vulnerable.
not_vuln = FALSE;
pattern = "^5.0.([0-3])(?: MR ([0-9]+))? ";
prod = get_kb_item_or_exit("BlackBerry_ES/Product");
version = get_kb_item_or_exit("BlackBerry_ES/Version");
if ("Enterprise Server" >!< prod)
{
  not_vuln = TRUE;
}
else if (version !~ "^5\.0\.[0-3] ")
{
  not_vuln = TRUE;
}
else if ("Microsoft Exchange" >< prod)
{
  matches = eregmatch(string:version, pattern:pattern);
  if (
    !isnull(matches) &&
    ((matches[1] == 2 && !isnull(matches[2]) && matches[2] >= 5) ||
     (matches[1] == 3 && !isnull(matches[2]) && matches[2] >= 1))
  ) not_vuln = TRUE;
}
else if ("IBM Lotus Domino" >< prod)
{
  matches = eregmatch(string:version, pattern:pattern);
  if (
    !isnull(matches) &&
    matches[1] == 3 && !isnull(matches[2]) && matches[2] >= 1
  ) not_vuln = TRUE;
}
else if ("Novell GroupWise" >< prod)
{
  matches = eregmatch(string:version, pattern:pattern);
  if (
    !isnull(matches) &&
    ((matches[1] > 1) ||
     (matches[1] == 1 && !isnull(matches[2]) && matches[2] > 2))
  ) not_vuln = TRUE;
}
else
{
  exit(0, prod + " is not on a recognized platform.");
}

if (not_vuln) exit(0, prod + " " + version + " is not vulnerable.");

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

# Try to connect to server.
if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

# Split the software's location into components.
base = get_kb_item_or_exit("BlackBerry_ES/Path");
path = "\BAS\server\default\deploy\basclientwebdesktop.war\WEB-INF";
share = ereg_replace(string:base, pattern:"^([A-Za-z]):.*", replace:"\1$");
dir = ereg_replace(string:base, pattern:"^[A-Za-z]:(.*)", replace:"\1");
path_class = "\classes\com\rim\bes\bas\web\desktop\pages\base\WDLayoutBase.class";
path_jar = "\lib\bas.client.webCommon-1.0.jar";
NetUseDel(close:FALSE);

# Connect to the share software is installed on.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Failed to connect to " + share + " share.");
}

# Get MD5 of class file.
md5_class = md5_file(path:dir + path + path_class);
if (isnull(md5_class))
{
  NetUseDel();
  exit(1, "Failed to open " + dir + path + path_class + ".");
}

# Get MD5 of jar file.
md5_jar = md5_file(path:dir + path + path_jar);
if (isnull(md5_jar))
{
  NetUseDel();
  exit(1, "Failed to open " + dir + path + path_jar + ".");
}

# Clean up.
NetUseDel();

# Determine what the MD5s should be.
fixed_class = NULL;
fixed_jar = NULL;
if (version =~ "^5.0.1")
{
  fix = "Service Pack 1 Interim Security Software Update for April 12th 2011";
  if (prod =~ "(Microsoft Exchange|IBM Lotus Domino)")
  {
    fixed_class = "ca757661ee6784eea2e23c2a92165db1";
    fixed_jar = "18b0d7445577d463242c20db8f00b5b6";
  }
  else if ("Novell GroupWise" >< prod)
  {
    fixed_class = "d67b5a76e6bdc7f82be4ac270b6cb297";
    fixed_jar = "662e20ed9c3a92d73cb25648854a8b52";
  }
}
else if (prod =~ "^5.0.2")
{
  fix = "Service Pack 2 Interim Security Software Update for April 12th 2011";
  fixed_class = "06dec1731f1812f2a040bc9d42a8677f";
  fixed_jar = "39d09f84b31972f249ace151e3234908";
}
else if (prod =~ "^5.0.3")
{
  fix = "Service Pack 3 Maintenance Release 1";
}

# Check if fix is installed.
if (md5_class == fixed_class && md5_jar == fixed_jar)
  exit(0, prod + " " + version + " on the remote host has been fixed and is not affected.");

if (report_verbosity > 0)
{
  report =
    '\n  Product           : ' + prod +
    '\n  Path              : ' + base +
    '\n  Installed version : ' + version +
    '\n';

  if (!isnull(fixed_class) && md5_class != fixed_class)
    report +=
      '\n' + base + path + path_class + ' needs to be updated.' +
      '\n  Installed MD5     : ' + md5_class +
      '\n  Fixed MD5         : ' + fixed_class +
      '\n';

  if (!isnull(fixed_jar) && md5_jar != fixed_jar)
    report +=
      '\n' + base + path + path_jar + ' needs to be updated.' +
      '\n  Installed MD5     : ' + md5_jar +
      '\n  Fixed MD5         : ' + fixed_jar +
      '\n';

  report +=
    '\n  Install ' + fix + ' to correct the issue.' +
    '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
