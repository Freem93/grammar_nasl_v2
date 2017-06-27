#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(27527);
  script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2017/05/02 23:36:52 $");

  script_cve_id("CVE-2007-5472");
  script_bugtraq_id(26134);
  script_osvdb_id(37998);

  script_name(english:"CA Host-Based Intrusion Prevention System Server Log Data XSS");
  script_summary(english:"Checks date of ca/hss/config/SystemConstants.class in hss.jar");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a
cross-site scripting vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Computer Associates' Host-Based Intrusion
Prevention System (CA HIPS) Server, an intrusion prevention system for
Windows.

The version of CA HIPS Server installed on the remote Windows server
is reportedly affected by a cross-site scripting issue because it
fails to sanitize log data before displaying it. An attacker may be
able to leverage this issue to inject arbitrary HTML or script code
into the browser of an administrative user to be executed within the
security context of the affected service.");
 # https://web.archive.org/web/20071021110020/http://supportconnectw.ca.com/public/cahips/infodocs/cahips-secnotice.asp
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?52470381");
 script_set_attribute(attribute:"solution", value:
"Upgrade to CA HIPS version 8.0.0.93 by applying the patch referenced
in the vendor advisory above.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/10/18");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/23");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/name", "SMB/login", "SMB/password");
  script_require_ports(139, 445);

  exit(0);
}


include("byte_func.inc");
include("smb_func.inc");
include("audit.inc");


# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) exit(0);


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Determine where it's installed.
path = NULL;

key = "SOFTWARE\CA\HIPSManagementServer";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"HSSDir");
  if (!isnull(value))
  {
    path = value[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Determine the version from ca/hss/config/SystemConstants.class in hss.jar.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
jar =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\web\WEB-INF\lib\hss.jar", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:jar,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (isnull(fh))
{
  NetUseDel();
  exit(0);
}


# Find start / size of the zip file's central directory.
#
# nb: see <http://www.pkware.com/documents/casestudies/APPNOTE.TXT>.
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);
fsize = GetFileSize(handle:fh);
chunk = 200;                         # arbitrary, but works pretty well
if (fsize > chunk)
{
  data = ReadFile(handle:fh, length:chunk, offset:fsize-chunk);
  if (data)
  {
    eocdr = strstr(data, raw_string(0x50, 0x4b, 0x05, 0x06));
    if (eocdr && strlen(eocdr) > 20)
    {
      dir_size = getdword(blob:eocdr, pos:12);
      dir_ofs = getdword(blob:eocdr, pos:16);
    }
  }
}


# Find start of ca/hss/config/SystemConstants.class from zip file's central directory.
if (dir_ofs && dir_size)
{
  data = ReadFile(handle:fh, length:dir_size, offset:dir_ofs);
  if (data)
  {
    fname = stridx(data, "ca/hss/config/SystemConstants.classPK");
    if (
      fname >= 0 &&
      substr(data, fname-46, fname-43) == raw_string(0x50, 0x4b, 0x01, 0x02)
    )
    {
      fheader = substr(data, fname-46, fname);
      fmod_time = getword(blob:fheader, pos:0x0c);
      fmod_date = getword(blob:fheader, pos:0x0e);

      # Dates are stored as in MS-DOS:
      #
      #   Bits 	Content
      #   0-4 	Day of the month (1-31)
      #   5-8 	Month (1 = January, 2 = February, and so on)
      #   9-15 	Year offset from 1980 (add 1980 to get actual year)
      day = fmod_date & 0x1f;
      mon = (fmod_date >> 5) & 0x0f;
      year = (fmod_date >> 9) + 1980;

      # the modification date is before the date for the fix , 06-Sep-2007.
      if (
        # nb: a sanity check
        year >= 1980 && year <= 2007 && mon >= 1 && mon <= 12 && day >= 1 && day <= 31 &&
        (
          year < 2007 ||
          (
            year == 2007 &&
            (
              mon < 9 ||
              (mon == 9 && day < 6)
            )
          )
        )
      ) {
      	security_warning(port);
      	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	}
    }
  }
}
CloseFile(handle:fh);


# Clean up.
NetUseDel();
