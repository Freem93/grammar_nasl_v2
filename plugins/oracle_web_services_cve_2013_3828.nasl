#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71537);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/02/16 03:43:08 $");

  script_cve_id("CVE-2013-3828");
  script_bugtraq_id(63058);
  script_osvdb_id(98462);

  script_name(english:"Oracle Fusion Middleware Web Services Component Remote Information Disclosure");
  script_summary(english:"Checks for unpatched Web Services install");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is affected by an information disclosure
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is affected by an information disclosure vulnerability
that is related to the 'ScriptServlet' class in the Web Services Test
Page.  This vulnerability can be triggered via a specially crafted query
with a directory traversal string."
  );
  # http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac29c174");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-249/");
  script_set_attribute(attribute:"solution", value:"Apply Oracle October 2013 CPU.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("bsal.inc");
include("byte_func.inc");
include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("zip.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

name   = kb_smb_name();
port   = kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

appname = 'Oracle Web Services';

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\ORACLE";
subkeys = get_registry_subkeys(handle:hklm, key:key);

if (isnull(subkeys))
{
  RegCloseKey(handle:hklm);
  close_registry();
  audit(AUDIT_NOT_INST, "Oracle Fusion Middleware");
}

oracle_homes = make_list();

foreach subkey (subkeys)
{
  if (subkey !~ "^KEY_") continue;

  key2 = key + "\" + subkey + "\ORACLE_HOME";
  path = get_registry_value(handle:hklm, item:key2);
  if (!isnull(path))
  {
    if (path[strlen(path) - 1] != "\") path += "\";
    oracle_homes = make_list(oracle_homes, path);
  }
}

RegCloseKey(handle:hklm);
close_registry(close:FALSE);

if (max_index(oracle_homes) == 0)
{
  close_registry();
  audit(AUDIT_NOT_INST, "Oracle Fusion Middleware");
}

test_jar_locations = make_list("modules\oracle.webservices_11.1.1",
                               "webservices\lib");

test_jars = make_list();

# check middleware homes for potentially vulnerable files
foreach home (oracle_homes)
{
  foreach location (test_jar_locations)
  {
    jar = home + location + "\testpage.jar";
    if (hotfix_file_exists(path:jar)) test_jars = make_list(test_jars, jar);
  }
}

if (max_index(test_jars) == 0)
{
  hotfix_check_fversion_end();
  audit(AUDIT_NOT_INST, appname);
}

report = '';

# check to see if jar files have been patched
foreach jar (test_jars)
{
  file = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1", string:jar);
  share = hotfix_path2share(path:jar);

  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1) continue;

  fh = CreateFile(
    file:file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (isnull(fh)) continue;

  fsize = GetFileSize(handle:fh);
  off = 0;
  # Read in the file
  file_contents = '';
  while (off <= fsize)
  {
    data = ReadFile(handle:fh, length:10240, offset:off);
    if (strlen(data) == 0) break;
    file_contents += data;
    off += 10240;
  }
  CloseFile(handle:fh);

  if (file_contents == '') continue;

  # see if vulnerable class exists
  res = zip_parse(blob:file_contents, "oracle/j2ee/ws/testpage/ScriptServlet.class");

  if (!isnull(res) && res != '')
  {
    if ("oracle.webservices_11.1.1" >< jar)
    {
      middleware_home = jar - "modules\oracle.webservices_11.1.1\testpage.jar";
      patch = '16920856';
    }
    else
    {
      patch = '16920865';
      middleware_home = jar - "webservices\lib\testpage.jar";
    }

    report += '\n  Middleware home    : ' + middleware_home +
              '\n  Unpatched Jar file : ' + jar +
              '\n  Patch required     : ' + patch + '\n';
  }
}

# cleanup
NetUseDel();

if (report == '') audit(AUDIT_INST_VER_NOT_VULN, appname);

if (report_verbosity > 0) security_warning(port:port, extra:report);
else security_warning(port);
