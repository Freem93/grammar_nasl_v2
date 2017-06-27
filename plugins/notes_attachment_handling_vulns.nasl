#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20924);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/11/23 20:31:34 $");

  script_cve_id("CVE-2005-2618", "CVE-2005-2619");
  script_bugtraq_id(16576);
  script_osvdb_id(23064, 23065, 23066, 23067, 23068, 88200);
  script_xref(name:"Secunia", value:"16280");

  script_name(english:"Lotus Notes < 6.5.5 / 7.0.1 Attachment Handling Vulnerabilities");
  script_summary(english:"Checks for attachment handling vulnerabilities in Lotus Notes");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows application is prone to multiple flaws.");
  script_set_attribute(attribute:"description", value:
"The version of Lotus Notes installed on the remote host reportedly
contains five buffer overflow vulnerabilities and one directory
traversal vulnerability in the KeyView viewers used to handle message
attachments. By sending specially crafted attachments to users of the
affected application and getting them to double-click and view the
attachment, an attacker may be able to execute arbitrary code subject
to the privileges under which the affected application runs or to
delete arbitrary files that are accessible to the NOTES user.");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21229918");
  script_set_attribute(attribute:"solution", value:
"Either edit the 'keyview.ini' configuration file as described in the
vendor advisory above or upgrade to Lotus Notes version 6.5.5 / 7.0.1
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22, 119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_notes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl","lotus_notes_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated","SMB/Lotus_Notes/Installed");
  script_require_ports("Services/notes", 139, 445);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");

appname = "IBM Lotus Notes";
kb_base = "SMB/Lotus_Notes/";

path = get_kb_item_or_exit(kb_base + 'Path');
path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);

str_version = get_kb_item_or_exit(kb_base + 'Version');
version = split(str_version, sep:'.', keep:FALSE);

# If it's an affected version...
#
# nb: version[2] is multiplied by 10.
if (
  int(version[0]) < 6 ||
  (
    int(version[0]) == 6 &&
    (
      int(version[1]) < 5 ||
      int(version[1]) == 5 && int(version[2]) < 50
    )
  ) ||
  (
    int(version[0]) == 7 && int(version[1]) == 0 && int(version[2]) < 10
  )
)
{
  # Connect to the appropriate share.
  get_kb_item_or_exit("SMB/Registry/Enumerated");
  port    =  kb_smb_transport();
  login   =  kb_smb_login();
  pass    =  kb_smb_password();
  domain  =  kb_smb_domain();

  if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, share);
  }

  # Read the KeyView INI file.
  ini = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\keyview.ini", string:path);
  fh = CreateFile(
    file:ini,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh))
  {
    NetUseDel();
    exit(0, "Failed to open '"+(share-'$')+":"+ini+"'.");
  }
  # but no read more than 10K.
  data = '';
  chunk = 10240;
  size = GetFileSize(handle:fh);
  if (size > 0)
  {
    if (chunk > size) chunk = size;
    data = ReadFile(handle:fh, length:chunk, offset:0);
    CloseFile(handle:fh);
  }

  if (data)
  {
    # Affected DLLs.
    dlls = make_list("tarrdr.dll", "uudrdr.dll", "htmsr.dll");

    # Check whether affected DLLs are referenced.
    foreach dll (dlls)
    {
      # If so, check whether file exists.
      if (egrep(pattern:string("^[0-9]+=", dll), string:data))
      {
        file =  str_replace(find:"keyview.ini", replace:dll, string:ini);
        fh = CreateFile(
          file:file,
          desired_access:GENERIC_READ,
          file_attributes:FILE_ATTRIBUTE_NORMAL,
          share_mode:FILE_SHARE_READ,
          create_disposition:OPEN_EXISTING
        );

        # There's a problem if it does.
        if (fh)
        {
          security_hole(port);
          CloseFile(handle:fh);
          NetUseDel();
          exit(0);
        }
      }
    }
  }
  NetUseDel();
  audit(AUDIT_INST_PATH_NOT_VULN, appname, str_version, path);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, str_version, path);
