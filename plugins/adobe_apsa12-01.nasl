#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62693);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/04/27 14:49:39 $");
  script_xref(name:"IAVB", value:"2012-B-0099");
  script_xref(name:"IAVB", value:"2012-B-0100");

  script_name(english:"Adobe Software Signed By Revoked Certificate (APSA12-01)");
  script_summary(english:"Checks the digital signature of adobe apps");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is signed by a
revoked certificate.");
  script_set_attribute(attribute:"description", value:
"The remote host is using Adobe software that has been digitally signed
by a revoked certificate. An Adobe build server was compromised, which
has caused at least two malicious utilities to be signed with Adobe's
code signing certificate. Any software signed by this revoked
certificate (including legitimate Adobe software) is no longer
trusted.

This plugin checks if the following software has been signed by the
revoked certificate :

  - Adobe Bridge
    - Adobe Extension Manager CS6
    - Adobe Media Encoder CS6
    - Adobe Premiere Pro CS6
    - Adobe Reader
    - Audition CS6
    - ColdFusion 10
    - Configurator 3.1
    - Contribute 6.5
    - Dreamweaver CS6
    - Drive 4
    - Encore CS6
    - Flash Player
    - Flash Professional CS6
    - Illustrator CS6
    - Photoshop CS6
    - Prelude CS6
    - Presenter 8
    - Shockwave Player
    - SpeedGrade CS6");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/advisories/apsa12-01.html");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/x-productkb/global/certificate-updates.html");
  # http://blogs.adobe.com/asset/2012/09/inappropriate-use-of-adobe-code-signing-certificate.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd0ed764");
  script_set_attribute(attribute:"solution", value:
"Update all affected Adobe applications to the latest version. Refer to
Adobe security advisory APSA12-01 for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("adobe_photoshop_installed.nasl", "flash_player_installed.nasl", "adobe_audition_installed.nasl", "adobe_illustrator_installed.nasl", "adobe_dreamweaver_installed.nasl", "flash_professional_installed.nasl", "adobe_bridge_installed.nasl", "shockwave_player_apsb09_08.nasl", "adobe_encore_installed.nasl", "adobe_premiere_pro_installed.nasl", "adobe_ext_mgr_installed.nasl", "adobe_contribute_installed.nasl", "adobe_drive_installed.nasl", "adobe_speedgrade_installed.nasl", "adobe_presenter_installed.nasl", "adobe_prelude_installed.nasl", "adobe_reader_installed.nasl", "adobe_configurator_installed.nasl", "adobe_media_encoder_installed.nasl", "coldfusion_win_local_detect.nasl");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

REVOKED_CERT_SHA1_HASH = 'FDF01DD3F37C66AC4C779D92623C77814A07FE4C';
REVOKED_CERT_SERIAL_NUMBER = '15E5AC0A487063718E39DA52301A0488';

##
# recursively decodes pkcs7 data, determining if it contains the revoked cert
#
# @anonparam data asn.1 encoded data
# @return TRUE if data contains the revoked cert,
#         FALSE otherwise
##
function _contains_revoked_cert()
{
  local_var data, pos, signing_time_start, res, tag, set, utc, serial, sha1hash;
  local_var oid, next, version, certs, cert_list_len, cert, cert_data, serial_num;
  data = _FCT_ANON_ARGS[0];
  pos = 0;

  res = der_decode(data:data, pos:0);
  tag = res[0];
  data = res[1];
  if (!(tag & 0x20)) return NULL;

  res = der_decode(data:data, pos:0);
  tag = res[0];
  oid = res[1];
  next = res[2];
  # verify this is pkcs7-signedData
  if (tag != 0x06 || der_decode_oid(oid:oid) != '1.2.840.113549.1.7.2') return NULL;

  res = der_decode(data:data, pos:next);
  tag = res[0];
  data = res[1];
  if (!(tag & 0x20)) return NULL;

  res = der_decode(data:data, pos:0);
  tag = res[0];
  data = res[1];
  if (!(tag & 0x20)) return NULL;

  version =  der_parse_int(i:data);
  res = der_decode(data:data, pos:0);
  next = res[2];
  if (version != 1) return NULL;

  res = der_decode(data:data, pos:next);
  next = res[2];  # pointer to sequence of digest algorithms
  res = der_decode(data:data, pos:next);
  next = res[2];  # pointer to sequence of (?)
  res = der_decode(data:data, pos:next);
  certs = res[1];  # pointer to sequence of certs (?)
  if (!(tag & 0x20)) return NULL;

  cert_list_len = strlen(certs);
  pos = 0;

  while (pos < cert_list_len)
  {
    res = der_decode(data:certs, pos:pos);
    next = res[2];

    cert = substr(certs, pos, next - 1);
    pos = next;

    if (toupper(hexstr(SHA1(cert))) == REVOKED_CERT_SHA1_HASH)
    {
      cert_data = der_decode(data:cert);
      cert_data = der_decode(data:cert_data[1]);
      res = der_decode(data:cert_data[1]);
      res = der_decode(data:cert_data[1], pos:res[2]);
      serial_num = toupper(hexstr(res[1]));

      if (serial_num == REVOKED_CERT_SERIAL_NUMBER)
      {
        return TRUE;
      }
    }
  }
}

##
# extracts the digital signature (pkcs7) from an exe
#
# @anonparam fh file handle of file to extract signature from
# @return
function _get_pkcs7_sig()
{
  local_var fh, dos_header, e_lfanew, offset, sig_len, unknown, sig, data_dir_cert_offset, cert_rva, machine;
  fh = _FCT_ANON_ARGS[0];
  dos_header = ReadFile(handle:fh, offset:0, length:64);
  e_lfanew = get_dword(blob:dos_header, pos:60);
  machine = ReadFile(handle:fh, offset:e_lfanew + 4, length:2);
  set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);
  machine = get_word(blob:machine, pos:0);
  set_byte_order(BYTE_ORDER_BIG_ENDIAN);

  # determine whether or not this is a 32 bit executable in order to determine the offset to the
  # digital signatures (some dword fields in 32 bit files are qwords in 64 bit files)
  if (machine == 0x014c)  # 32 bits
    data_dir_cert_offset = e_lfanew + 24 + 128; # + file header + offset to cert data dir rva
  else if (machine == 0x8664 || machine == 0x2000) # 64 bits (amd64, itanium)
    data_dir_cert_offset = e_lfanew + 24 + 144; # + file header + offset to cert data dir rva
  else # unknown machine type
    return NULL;

  cert_rva = ReadFile(handle:fh, offset:data_dir_cert_offset, length:4);
  cert_rva = get_dword(blob:cert_rva, pos:0);
  if (cert_rva == 0)
    return NULL;

  sig_len = ReadFile(handle:fh, offset:cert_rva, length:4);
  set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);
  sig_len = getdword(blob:sig_len, pos:0);
  set_byte_order(BYTE_ORDER_BIG_ENDIAN);
  unknown = ReadFile(handle:fh, offset:cert_rva + 4, length:4); offset += 4;  # constant (\x00\x02\x02\x00)
  sig = ReadFile(handle:fh, offset:cert_rva + 8, length:sig_len - 4 - 4);  # subtract the length & unknown constant

  return sig;
}

#
# execution begins here
#

app_names['SMB/Adobe_Photoshop/*/Path'] = 'Photoshop';
app_files['SMB/Adobe_Photoshop/*/Path'] = 'photoshop.exe';
app_names['SMB/Flash_Player/*/File/*'] = 'Flash Player';
app_files['SMB/Flash_Player/*/File/*'] = ''; # the path in the KB already includes the filename
app_names['SMB/Adobe_Audition/*/ExePath'] = 'Audition';
app_files['SMB/Adobe_Audition/*/ExePath'] = ''; # the path in the KB already includes the filename
app_names['SMB/Adobe_Premiere_Pro/*/ExePath'] = 'Premiere Pro';
app_files['SMB/Adobe_Premiere_Pro/*/ExePath'] = ''; # the path in the KB already includes the filename
app_names['SMB/Adobe_SpeedGrade/*/ExePath'] = 'SpeedGrade';
app_files['SMB/Adobe_SpeedGrade/*/ExePath'] = ''; # the path in the KB already includes the filename
app_names['SMB/Adobe_Encore/*/ExePath'] = 'Encore';
app_files['SMB/Adobe_Encore/*/ExePath'] = ''; # the path in the KB already includes the filename
app_names['SMB/Adobe_Prelude/*/ExePath'] = 'Prelude';
app_files['SMB/Adobe_Prelude/*/ExePath'] = ''; # the path in the KB already includes the filename
app_names['SMB/Adobe Illustrator/path'] = 'Illustrator';
app_files['SMB/Adobe Illustrator/path'] = 'Illustrator.exe';
app_names['SMB/Adobe_Presenter/*/Path'] = 'Presenter';
app_files['SMB/Adobe_Presenter/*/Path'] = 'TestPresenter.exe';
app_names['SMB/Adobe_Dreamweaver/*/Path'] = 'Dreamweaver';
app_files['SMB/Adobe_Dreamweaver/*/Path'] = 'Dreamweaver.exe';
app_names['SMB/Adobe_Contribute/*/Path'] = 'Contribute';
app_files['SMB/Adobe_Contribute/*/Path'] = 'Contribute.exe';
app_names['SMB/Adobe Flash Professional/Installs/*'] = 'Flash Professional';
app_files['SMB/Adobe Flash Professional/Installs/*'] = 'Flash.exe';
app_names['SMB/Adobe_Drive/*/Path'] = 'Drive';
app_files['SMB/Adobe_Drive/*/Path'] = 'ConnectUI\\Adobe Drive.exe';
app_names['SMB/Adobe_Bridge/*/Path'] = 'Bridge';
app_files['SMB/Adobe_Bridge/*/Path'] = 'Bridge.exe';
app_names['SMB/shockwave_player/*/path'] = 'Shockwave Player';
app_files['SMB/shockwave_player/*/path'] = ''; # the path in the KB already includes the filename
app_names['SMB/Adobe_Media_Encoder/*/ExePath'] = 'Media Encoder';
app_files['SMB/Adobe_Media_Encoder/*/ExePath'] = ''; # the path in the KB already includes the filename
app_names['SMB/Adobe_Extension_Manager/*/ExePath'] = 'Extension Manager';
app_files['SMB/Adobe_Extension_manager/*/ExePath'] = ''; # the path in the KB already includes the filename
app_names['SMB/Adobe_Configurator/ExePath'] = 'Configurator';
app_files['SMB/Adobe_Configurator/ExePath'] = ''; # the path in the KB already includes the filename
app_names['SMB/Acroread/*/Path'] = 'Reader';
app_files['SMB/Acroread/*/Path'] = 'AcroRd32.dll';
app_names['SMB/coldfusion/*/cfroot'] = 'ColdFusion 10';
app_files['SMB/coldfusion/*/cfroot'] = 'lib\\adobe.cer';
installs_checked = 0;

name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) audit(AUDIT_SOCK_FAIL, port);
#session_init(socket:soc, hostname:name);

if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');


affected_files = make_list();
vuln_apps = make_array(); # key - appname, value - list of pathnames

foreach kb_key (keys(app_names))
{
  file = app_files[kb_key];
  app_name = app_names[kb_key];
  paths = get_kb_list(kb_key);

  foreach path (paths)
  {
    # add a trailing backslash if the path is a directory and doesn't already have one
    if (file != '' && path[strlen(path) - 1] != "\")
      path += "\";
    path += file;
    path_parts = split(path, sep:':', keep:FALSE);
    share = path_parts[0] + '$';
    exe = path_parts[1];

    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (rc != 1)
    {
      #debug_print("Can't connect to "+share+" share.");
      NetUseDel(close:FALSE);
      continue;
    }

    fh = CreateFile(
      file:exe,
      desired_access:FILE_READ_DATA,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );

    if (!isnull(fh))
    {
      # this is a slight hack - all files being checked are PE executables with a .exe extension
      # which contain a signature that needs to be extracted and analyzed to see if it's been signed
      # by the revoked certificate.
      #
      # currently the only exception to this is ColdFusion 10. for CF10 the plugin just reads the
      # certificate file, calculates the SHA1 hash, and checks if it matches the known bad certificate
      if (exe =~ '.exe')
      {
        sig = _get_pkcs7_sig(fh);
        vuln = _contains_revoked_cert(sig);
      }
      else
      {
        vuln = FALSE;
        size = GetFileSize(handle:fh);

        if (size < 4096) # sanity checking (the file should be about 1306 bytes)
        {
          cert = ReadFile(handle:fh, length:size, offset:0);
          fingerprint = toupper(hexstr(SHA1(cert)));
          vuln = fingerprint == REVOKED_CERT_SHA1_HASH;
        }
      }

      CloseFile(handle:fh);
      installs_checked++;

      if (vuln)
      {
        if (isnull(vuln_apps[app_name]))
          vuln_apps[app_name] = make_list(path);
        else
          vuln_apps[app_name] = make_list(vuln_apps[app_name], path);
      }
    }

    NetUseDel(close:FALSE);
  }
}

NetUseDel();

if (installs_checked == 0)
  exit(0, 'None of the affected Adobe applications were detected.');
if (max_index(keys(vuln_apps)) == 0)
  exit(0, 'The Adobe applications installed on the host are not affected.');

if (report_verbosity > 0)
{
  report +=
    '\nThe following files were either signed by, or contain the revoked' +
    '\ncertificate in APSA12-01:\n\n' +
    'Serial number : ' + REVOKED_CERT_SERIAL_NUMBER + '\n' +
    'SHA1 thumbprint : ' + REVOKED_CERT_SHA1_HASH + '\n';

  foreach app (sort(keys(vuln_apps)))
    report += '\n' + app + '\n' + join(vuln_apps[app], sep:'\n') + '\n';

  security_warning(port:port, extra:report);
}
else security_warning(port);
