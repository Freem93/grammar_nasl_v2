#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51389);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/04/14 20:50:07 $");

  script_bugtraq_id(45498);

  script_name(english:"Kerio Control < 7.1.0 Build 1689 Remote Cache Poisoning");
  script_summary(english:"Checks version of winroute.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a program that is affected by a cache
poisoning vulnerability.");

  script_set_attribute(attribute:"description", value:
"The version of Kerio Control (formerly known as Kerio WinRoute)
installed on the remote host is earlier than 7.1.0 Build 1689. Such
versions are reportedly affected by a remote cache poisoning
vulnerability.

By sending specially crafted HTTP data over a non-HTTP TCP connection,
a remote, unauthenticated attacker may be able to trick the HTTP cache
into storing arbitrary data.

Note that this issue only affects Kerio Control installations that
have the HTTP Cache enabled.");
  script_set_attribute(attribute:"see_also", value:"http://www.kerio.com/support/security-advisories#1012");
  script_set_attribute(attribute:"see_also", value:"http://www.kerio.com/control/history");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 7.1.0 Build 1689 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("kerio_control_installed.nasl");
  script_require_keys("SMB/Kerio_Control/Path", "SMB/Kerio_Control/Version", "SMB/Kerio_Control/Build");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

path = get_kb_item_or_exit("SMB/Kerio_Control/Path");
version = get_kb_item_or_exit("SMB/Kerio_Control/Version");
build = get_kb_item_or_exit("SMB/Kerio_Control/Build");

fixed_version = '7.1.0.1689';
if (ver_compare(ver:version+'.'+build, fix:fixed_version, strict:FALSE) == -1)
{
  # Unless we're paranoid, Check winroute.cfg for HTTP Cache
  if (report_paranoia < 2)
  {
    # Connect to the appropriate share.
    name    =  kb_smb_name();
    port    =  kb_smb_transport();

    login   =  kb_smb_login();
    pass    =  kb_smb_password();
    domain  =  kb_smb_domain();


    share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
    cfg =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\winroute.cfg", string:path);

    if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
    rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
    if (rc != 1)
    {
      NetUseDel();
      exit(1, "Can't connect to IPC$ share.");
    }
    NetUseDel(close:FALSE);

    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (rc != 1)
    {
      NetUseDel();
      exit(1, "Can't connect to "+share+" share.");
    }

    fh = CreateFile(
      file:cfg,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (isnull(fh))
    {
      NetUseDel();
      exit(1, "Failed to open '"+cfg+"'.");
    }
    fsize = GetFileSize(handle:fh);
    off = 0;

    http_cache = NULL;
    while (fsize > 0 && off <= fsize)
    {
      data = ReadFile(handle:fh, length:16384, offset:off);
      if (strlen(data) == 0) break;

      if ('<table name="Cache">' >< data)
      {
        cache_block = strstr(data, '<table name="Cache">');
        cache_block = cache_block - strstr(cache_block, '</table>');
        if ('<variable name="Enabled">' >< cache_block)
        {
          http_cache = ereg_replace(string:cache_block, pattern:'.*<variable name="Enabled">([0-9]+)</variable>.*', replace:"\1");
          break;
        }
      }
      else off += 16383;
    }
    CloseFile(handle:fh);
    NetUseDel();

    if (isnull(http_cache) || http_cache !~ '^[0-9]+')
    {
      exit(1, "Nessus was unable to determine if the install has HTTP Cache enabled.");
    }
    # Make sure http_cache isn't a string
    http_cache = int(http_cache);
    if (!http_cache)
    {
      exit(0, "Kerio Control version "+version+" Build "+build+" is installed but not affected because the HTTP Cache is disabled.");
    }
  }
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version + ' Build ' + build +
      '\n  Fixed version     : 7.1.0 Build 1689\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
exit(0, "Kerio Control "+version+" is installed and not affected.");
