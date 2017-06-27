#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33141);
  script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2016/11/11 20:19:26 $");

  script_cve_id("CVE-2008-2703", "CVE-2008-2704");
  script_bugtraq_id(29602);
  script_osvdb_id(46041, 46458);
  script_xref(name:"Secunia", value:"30576");

  script_name(english:"Novell GroupWise Messenger Client < 2.0.3 HP1 Multiple Remote Overflows");
  script_summary(english:"Check the version of GroupWise Messenger Client");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple buffer overflow vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote host is running GroupWise Messenger Client from Novell.

The installed version is affected by multiple buffer overflow
vulnerabilities. By sending specially crafted spoofed server responses
to valid client requests, it may be possible to execute arbitrary code
within the context of the application or cause a denial of service
condition.");
 script_set_attribute(attribute:"see_also", value:"http://download.novell.com/Download?buildid=HHSfPO91pLQ~");
 script_set_attribute(attribute:"solution", value:"Upgrade to Novell GroupWise Messenger Client 2.0.3 HP1.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Novell GroupWise Messenger Client Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_cwe_id(20, 119);

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/11");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("global_settings.inc");
include("audit.inc");

# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);

name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) exit(0);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) exit(0);

#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}

# Check if Novell Messenger Client is installed.

path = NULL;
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\NMCL32.EXE";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(item)) path = item[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

# If it is present, try to read a file that contains the
# version info.
buff = NULL;

if (path)
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  ver_file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\nmcl32.ver", string:path);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(0);
  }

  fh = CreateFile(
    file:ver_file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (!isnull(fh))
  {
    buff = ReadFile(handle:fh, length:2048, offset:0);
    CloseFile(handle:fh);
  }
}

NetUseDel();

if (buff)
{
  # nb: In pre HP 1 buff should look like
  # version=2.0.3
  # date=5/9/2007 9:53:22
  #

  ver = egrep(pattern:"^version=([0-2]+\.0(|.[0-3]$))",string:buff);
  ver = chomp(ver);
  ver = ereg_replace(pattern:"^version=([0-2]+\.0(|.[0-3]$))",string:ver,replace:"\1") ;

  date = egrep(pattern:"^date=([0-9]+/[0-9]+/[0-9]+) .+$",string:buff);
  date = chomp(date);
  date = ereg_replace(pattern:"^date=([0-9]+/[0-9]+/[0-9]+) .+$",string:date,replace:"\1");

 if (isnull(ver) || isnull(date)) exit (0);

  v = split(ver, sep:".", keep:FALSE);
  for(i = 0 ; i < max_index(ver); i++)
   v[i] = int(v[i]);

  d = split(date, sep:"/", keep:FALSE);

  if ( ( v[0] == 2 && v[1] == 0 && isnull(v[2]) ) ||
       ( v[0] == 2 && v[1] == 0 && v[2] < 3) ||
       ( v[0] == 2 && v[1] == 0 && v[2] == 3 && int(d[2]) < 2008 ) ||
       ( v[0] == 2 && v[1] == 0 && v[2] == 3 && int(d[2]) == 2008 &&  int(d[1]) < 5 )
     )
     {
      if (report_verbosity)
        {
	  report = string(
          "\n",
          " GroupWise Messenger Client version, ",ver,"\n",
	  " is installed on the remote system.\n",
	  " It was last updated on ",date,"\n");

	  security_hole(port:port,extra:report);
        }
       else
       security_hole(port);
     }
}
