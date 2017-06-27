#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");
include("obj.inc");

if (description)
{
  script_id(81425);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/11/24 15:06:48 $");

  script_cve_id("CVE-2015-2077", "CVE-2015-2078");
  script_bugtraq_id(72693);
  script_osvdb_id(118562, 118638);
  script_xref(name:"CERT", value:"529496");

  script_name(english:"Komodia SSL Digestor Root CA Certificate Installed (Superfish)");
  script_summary(english:"Checks the registry for a Komodia-related root CA cert.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a man-in-the-middle
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has an application installed that uses the
Komodia SSL Digestor SDK (e.g. Superfish Visual Discovery and
KeepMyFamilySecure). It is, therefore, affected by an HTTPS
man-in-the-middle vulnerability due to the installation of a
non-unique root CA certificate associated with the SDK into the
Windows trusted system certificate store. The private keys for many of
these root CAs are publicly known. Furthermore, the SDK is insecurely
implemented and websites that use specially crafted self-signed
certificates will be reported as trusted to the user. Individual
Firefox and Thunderbird profiles may also contain the compromised root
CA certificates.

A MitM attacker can exploit this vulnerability to read and/or modify
communications encrypted via HTTPS without the user's knowledge.");
  # https://forums.lenovo.com/t5/Lenovo-P-Y-and-Z-series/Lenovo-Pre-instaling-adware-spam-Superfish-powerd-by/td-p/1726839
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1658aef1");
  script_set_attribute(attribute:"see_also", value:"http://blog.erratasec.com/2015/02/extracting-superfish-certificate.html");
  # https://www.facebook.com/notes/protect-the-graph/windows-ssl-interception-gone-wild/1570074729899339
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?235e60a1");
  script_set_attribute(attribute:"see_also", value:"https://gist.github.com/Wack0/17c56b77a90073be81d3");
  script_set_attribute(attribute:"see_also", value:"https://blog.filippo.io/komodia-superfish-ssl-validation-is-broken/");
  script_set_attribute(attribute:"see_also", value:"http://support.lenovo.com/us/en/product_security/superfish");
  script_set_attribute(attribute:"see_also", value:"http://support.lenovo.com/us/en/product_security/superfish_uninstall");
  script_set_attribute(attribute:"solution", value:
"If Superfish is installed, uninstall the application and root CA
certificate using the instructions provided by Lenovo.

Otherwise, contact the vendor for information on how to uninstall the
application and the bundled root CA certificate.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/21"); # date where this was reported on Lenovo forums
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:komodia:redirector_sdk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
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

KOMODIA_CERTS = make_array(
  '7EB6FDD6914BAA8AFC239775B0EE8B96A7DD8D99', 'Covenant Eyes',
  'C659FBEB968ADAD2AA49F062C5AF0E4968EEB0A1', 'ImpresX',
  '00FD59DA1D4B560E4D04F202BE3050D81B8FA7B8', 'Easy Hide IP',
  'BE90F13A20F8DE5537BF62CFCD5B3CDEFD43B9EA', 'Hide My IP',
  'D468C4971AD856CC96F8B9B4B2D6A1B8040E26BD', 'Keep My Family Secure',
  'B49438B65F42E2CB43666BC23CFFE531CE7F6D46', 'Kurupira Web Filter',
  'F011277697203AA3EFBFA3482C3FED7A108DD2D8', 'Ad-Aware Web Companion',
  '964DF5DAE0B1405A70B92015001B27BF08D808BB', 'PureLeads',
  '27980262382C7BA633E1E6879428D67B13FE7429', 'Qustodio', # OS X only?
  '653B739F5898BB9C031B1DBCED66E131FDC6BCB8', 'Qustodio',
  '4594FF3C3AF8287A40DC029820C3D37A1251D6B3', 'SecureTeen',
  '684358951E145303D8AAD4A16C4034F72B454FB5', 'StaffCop',
  'C864484869D41D2B0D32319C5A62F9315AAF2CBD', 'Superfish',
  'FF1F6CD8315EBB20B9378CA40C6AB5B5EF4B239A', 'WebProtect'
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
      foreach sig (keys(KOMODIA_CERTS))
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

  foreach thumbprint (keys(KOMODIA_CERTS))
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
# SMB Reg ops
ms_certs = _check_mscertstore();
prof_dir = _get_user_root_dir();
if(isnull(prof_dir))
{
  close_registry();
  exit(1,"Could not determine the directory under which user profiles are stored");
}

# SMB File IO
addirs   = _get_user_appdata_dirs(root:prof_dir);
ff_certs = _check_mozilla_cert8dbs(addirs:addirs,app:"Firefox");
tb_certs = _check_mozilla_cert8dbs(addirs:addirs,app:"Thunderbird");
close_registry();

report = "";

if(!empty_or_null(ms_certs))
{
  report +=
    '\nThe following root CA certificates associated with the Komodia SSL' +
    '\nDigestor SDK were detected in the Windows registry :\n';

  foreach sig (ms_certs)
  {
    report +=
      '\n  Application                  : ' + KOMODIA_CERTS[sig] +
      '\n  Root CA certificate location : HKEY_LOCAL_MACHINE\\Software\\Microsoft\\SystemCertificates\\ROOT\\Certificates\\' + sig + '\\Blob\n';
  }
}

if(!empty_or_null(ff_certs))
{
  if(report != "")
    report += '\n\n';

  report +=
  '\nRoot CA certificates associated with the Komodia SSL Digestor SDK were'+
  '\nfound in the following Firefox certificate stores :\n';
  foreach store (keys(ff_certs))
  {
    sigs = ff_certs[store];
    report +=
      '\n  Firefox certificate store : '+store;
    foreach sig (sigs)
    {
      report +=
        '\n    - ' + sig + " ("+KOMODIA_CERTS[sig]+")";
    }
  }
}

if(!empty_or_null(tb_certs))
{
  if(report != "")
    report += '\n\n';

  report +=
  '\nRoot CA certificates associated with the Komodia SSL Digestor SDK were'+
  '\nfound in the following Thunderbird certificate stores :\n';
  foreach store (keys(tb_certs))
  {
    sigs = tb_certs[store];
    report +=
      '\n  Thunderbird certificate store : '+store;
    foreach sig (sigs)
    {
      report +=
        '\n    - ' + sig + " ("+KOMODIA_CERTS[sig]+")";
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
