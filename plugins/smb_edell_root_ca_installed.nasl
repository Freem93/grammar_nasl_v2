#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");
include("obj.inc");

if (description)
{
  script_id(87013);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/29 19:33:19 $");

  script_osvdb_id(130575);
  script_xref(name:"CERT", value:"870761");
  script_xref(name:"CERT", value:"925497");

  script_name(english:"Dell eDellRoot / DSDTestProvider Root CA Certificates Installed");
  script_summary(english:"Checks the registry for eDellRoot and DSDTestProvider root CA certificates.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a man-in-the-middle
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a man-in-the-middle (MitM)
vulnerability due to the installation of a non-authorized root CA
certificate into the Windows trusted system certificate store. The
private keys for many of these root CAs are publicly known.
Furthermore, websites that use specially crafted self-signed
certificates will be reported as trusted to the user. Individual
Firefox and Thunderbird profiles may also contain the compromised root
CA certificates.

A MitM attacker can exploit this vulnerability to read and/or modify
communications encrypted via HTTPS without the user's knowledge.");
  script_set_attribute(attribute:"see_also", value:"https://zmap.io/dell/");
  script_set_attribute(attribute:"see_also", value:"http://www.dell.com/support/article/us/en/04/SLN300321");
  script_set_attribute(attribute:"solution", value:
"Uninstall the eDellRoot and DSDTestProvider root CA certificates per
the vendor knowledge base article.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:TF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_kb3119884.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated","SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("nsscertdb8.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');

CERT_SHA1_HASH_PROP_ID = 0x3;
CERT_MD5_HASH_PROP_ID = 0x4;
CERT_KEY_IDENTIFIER_PROP_ID = 0x14;
CERT_ISSUER_PUBLIC_KEY_MD5_HASH_PROP_ID = 0x18;
CERT_SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID = 0x19;
CERT_CERT_PROP_ID = 0x20;
CERT_FIRST_USER_PROP_ID = 0x8000;

WINVER = get_kb_item_or_exit("SMB/WindowsVersion");

EDELL_CERTS = make_array(
  '98A04E4163357790C4A79E6D713FF0AF51FE6927', 'eDellRoot',
  '02C2D931062D7B1DC2A5C7F5F0685064081FB221', 'DSDTestProvider'
);

##
# Parses the records contained in a certificate registry blob
#
# @anonparam blob the blob to parse
# @return a hash of records, where the key is the property ID and the value is the data
##
function _parse_blob()
{
  set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);
  local_var blob, ret, i, propid, rec_len, rec_data;
  blob = _FCT_ANON_ARGS[0];
  i = 0;
  ret = make_array();

  # try to parse the blob, one record at a time
  while (i < strlen(blob))
  {
    propid = get_dword(blob:blob, pos:i); i += 4;
    i += 4;  # this field is an unknown dword
    rec_len = get_dword(blob:blob, pos:i); i += 4;
    rec_data = substr(blob, i, i + rec_len - 1); i += rec_len;

    ret[propid] = rec_data;
  }

  return ret;
}

##
# Get the app data dir of users
# 
# @returns returns the root where user profiles are stored
#
function _get_user_root_dir()
{
  local_var hklm,pdir,key,systemroot;

  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  key  = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\ProfilesDirectory";
  pdir = get_registry_value(handle:hklm, item:key);

  if(isnull(pdir))
  {
    RegCloseKey(handle:hklm);
    return NULL;
  }

  if (stridx(tolower(pdir), "%systemdrive%") == 0)
  {
    key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot";
    systemroot = get_registry_value(handle:hklm, item:key);
    if (isnull(systemroot))
    {
      RegCloseKey(handle:hklm);
      exit(1, "Failed to get the system root on the remote host.");
    }
    systemroot = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1:", string:systemroot);
    pdir = systemroot + substr(pdir, strlen("%systemdrive%"));
    RegCloseKey(handle:hklm);
  }
  else
  {
    RegCloseKey(handle:hklm);
    return NULL;
  }

  return pdir;
}

##
# Gets user application directories
# 
# @param root user profile directory
#
##
function  _get_user_appdata_dirs(root)
{
  local_var dirpat,share,path,dirs,user,basedir,profiles;
  share = hotfix_path2share(path:root);
  basedir = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1", string:root);
  profiles = list_dir(
    basedir:basedir,
    dir_pat:"*",
    file_pat:".*",
    level:0,
    max_recurse:0,
    share:share
  );
  dirs = make_list();
  foreach user (profiles)
  {
    user = str_replace(string:user,find:basedir+"\",replace:"");
    path = NULL;
    if(user != '.' && user != '..')
    {
      if(WINVER < 6)
        path = root+'\\'+user+'\\Application Data';
      else
        path = root+'\\'+user+'\\AppData\\Roaming';
      dirs = make_list(dirs,path);
    }
  }
  return list_uniq(dirs);
}

##
# Check Mozilla product profiles for bad certificates
# 
# @param app    Mozilla app ("Firefox" or "Thunderbird")
# @param addirs List of AppData dirs for users on the system
#
##
function _check_mozilla_cert8dbs(addirs,app)
{
  local_var dbdat,dbpaths,dbpath,addir,sig,ret,found,share;

  if(app == "Firefox")
    app = "\Mozilla\Firefox\Profiles";
  else if(app == "Thunderbird")
    app = "\Thunderbird\Profiles";
  else
    return NULL;

  ret = make_array();
  foreach addir (addirs)
  {
    share = hotfix_path2share(path:addir);
    addir = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1", string:addir);

    dbpaths = list_dir(
      basedir:addir+app,
      file_pat:"^cert8.db$",
      level:0,
      max_recurse:2,
      share:share
    );

    foreach dbpath (dbpaths)
    {
      dbpath = str_replace(string:share, find:"$", replace:":")+dbpath;
      dbdat = hotfix_get_file_contents(dbpath);

      # File contents error 
      if(dbdat['error'] != HCF_OK) 
        continue;

      dbdat = cert8db_get_cert_sigs(dbdata:dbdat["data"]);

      # Cert store parsing error
      if(!isnull(dbdat["ERROR"])) 
        continue;

      dbdat = dbdat["SIGS"];
      found = make_list();
      foreach sig (keys(EDELL_CERTS))
      {
        if(!isnull(dbdat[sig]))
          found = make_list(found,sig);
      }

      if(!empty_or_null(found))
        ret[dbpath] = found;
    }
  }
  return ret;
}

function _check_mscertstore()
{
  local_var certs_found,hklm,thumbprint,reg_value,blob,der_cert,expected_thumbprint,calculated_thumbprint;
  certs_found = make_list();

  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

  foreach thumbprint (keys(EDELL_CERTS))
  {
    reg_value = "Software\Microsoft\SystemCertificates\ROOT\Certificates\" + thumbprint + "\Blob";
    blob = get_registry_value(handle:hklm, item:reg_value);
    if (isnull(blob)) continue;

    blob = _parse_blob(blob);
    der_cert = blob[CERT_CERT_PROP_ID];
    calculated_thumbprint = toupper(hexstr(SHA1(der_cert)));
    expected_thumbprint = toupper(thumbprint);
    if (calculated_thumbprint != expected_thumbprint) continue;

    certs_found = make_list(certs_found, thumbprint);
  }

  RegCloseKey(handle:hklm);

  return certs_found;
}

registry_init();

# Only check the MS cert. store if this out-of-band KB has not been applied
if (!get_kb_item("SMB/OOBKB/3119884"))
  ms_certs = _check_mscertstore();

prof_dir = _get_user_root_dir();
if(isnull(prof_dir))
{
  close_registry();
  exit(1,"Could not determine the directory under which user profiles are stored.");
}

# SMB File IO
addirs   = _get_user_appdata_dirs(root:prof_dir);
ff_certs = _check_mozilla_cert8dbs(addirs:addirs,app:"Firefox");
tb_certs = _check_mozilla_cert8dbs(addirs:addirs,app:"Thunderbird");
close_registry();

report = "";

if(!empty_or_null(ms_certs) && !get_kb_item("SMB/OOBKB/3119884"))
{
  report +=
    '\nThe following root CA certificates associated with eDellRoot CA' +
    '\nwere detected in the Windows registry :\n';

  foreach sig (ms_certs)
  {
    report +=
      '\n  Application                  : ' + EDELL_CERTS[sig] +
      '\n  Root CA certificate location : HKEY_LOCAL_MACHINE\\Software\\Microsoft\\SystemCertificates\\ROOT\\Certificates\\' + sig + '\\Blob\n';
  }
}

if(!empty_or_null(ff_certs))
{
  if(report != "")
    report += '\n\n';

  report +=
  '\nRoot CA certificates associated with the eDellRoot root CA'+
  '\nwere found in the following Firefox certificate stores :\n';
  foreach store (keys(ff_certs))
  {
    sigs = ff_certs[store];
    report +=
      '\n  Firefox certificate store : '+store;
    foreach sig (sigs)
    {
      report +=
        '\n    - ' + sig + " ("+EDELL_CERTS[sig]+")";
    }
  }
}

if(!empty_or_null(tb_certs))
{
  if(report != "")
    report += '\n\n';

  report +=
  '\nRoot CA certificates associated with the eDellRoot root CA'+
  '\nwere found in the following Thunderbird certificate stores :\n';
  foreach store (keys(tb_certs))
  {
    sigs = tb_certs[store];
    report +=
      '\n  Thunderbird certificate store : '+store;
    foreach sig (sigs)
    {
      report +=
        '\n    - ' + sig + " ("+EDELL_CERTS[sig]+")";
    }
  }
}

port = kb_smb_transport();
if (report != "" && report_verbosity > 0)
  security_warning(port:port, extra:report);
else if(report != "")
  security_warning(port);
else
 audit(AUDIT_HOST_NOT, 'affected');
