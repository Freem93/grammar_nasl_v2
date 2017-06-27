#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69334);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/08/14 04:20:16 $");

  script_name(english:"MS KB2862973: Update for Deprecation of MD5 Hashing Algorithm for Microsoft Root Certificate Program");
  script_summary(english:"Checks the registry");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing an update that improves cryptography and
digital certificate handling in Windows."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is missing Microsoft KB2862973, an update that
restricts the use of certificates with MD5 hashes.  This restriction is
limited to certificates issued under roots in the Microsoft root
certificate program.  This update increases the difficulty of some
spoofing, phishing, and man-in-the-middle attacks. 

Note that KB2862966 must also be installed in order for these changes to
have any effect."
  );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2862973");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/2862966");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8 and 2012 :

http://support.microsoft.com/kb/2862973"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");

  # this is more of a best practice than a fix for a vulnerability, so there's no vuln publication date
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("byte_func.inc");

port = kb_smb_transport();
get_kb_item_or_exit('SMB/WindowsVersion');
if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
names = make_list(
  'WeakMd5ThirdPartySha256Allow',
  'WeakMd5ThirdPartyFlags',
  'WeakMd5ThirdPartyAfterTime'
);
key = "Software\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainEngine\Config\default";
values = get_values_from_key(handle:hklm, entries:names, key:key);
RegCloseKey(handle:hklm);
close_registry();

whitelisted = values['WeakMd5ThirdPartySha256Allow'];
flags = values['WeakMd5ThirdPartyFlags'];
time = values['WeakMd5ThirdPartyAfterTime'];
key = "HKEY_LOCAL_MACHINE\" + key;

# if none of the data created by KB2862973 is present, it probably hasn't been installed
if (isnull(whitelisted) && isnull(flags) && isnull(time))
{
  if (report_verbosity > 0)
  {
    report =
      '\nIt appears KB2862973 has not been installed since the following' +
      '\nregistry key does not exist and/or does not contain any of the' +
      '\nfollowing values :\n\n' +
      key + '\n\n' +
      join(names, sep:'\n') + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}

# if the data is present, make sure it matches up with what is expected from KB2862973
expected_time = '00c029b8439ac901';
if (hexstr(time) != expected_time)
{
  if (report_verbosity > 0)
  {
    report =
      '\nIt appears KB2862973 has not been installed since the following' +
      '\nregistry value does not exist and/or does not contain the expected data :\n\n' +
      'Key : ' + key + '\n' +
      'Name : WeakMd5ThirdPartyAfterTime\n' +
      'Expected value : ' + expected_time + '\n';
    if (isnull(time))
      report += 'Actual value : (does not exist)\n';
    else
      report += 'Actual value : ' + hexstr(time) + '\n';

    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}

expected_flags = 0x88900000;
if ((flags & expected_flags) != expected_flags)
{
  if (report_verbosity > 0)
  {
    report =
      '\nIt appears KB2862973 has not been installed since the following' +
      '\nregistry value does not exist and/or does not contain the expected data :\n\n' +
      'Key : ' + key + '\n' +
      'Name : WeakMd5ThirdPartyFlags\n' +
      'Expected value : ' + expected_flags + '\n';
    if (isnull(time))
      report += 'Actual value : (does not exist)\n';
    else
      report += 'Actual value : ' + flags + '\n';

    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}

expected_thumbprints = make_array(
  '01A8F438E1A14A904BA530942BEDBD94708CA654B8DF3C4585F17B60DA6690D1', TRUE,
  '8421A0182C854C1F4266C95FC8302E217A14C7797FE41F2A87CA6B2734C43F1D', TRUE,
  '1AD335187A1DC540738FB2EA82B7366678C2EEDCDAE75FEADD6ECD89779CB983', TRUE,
  '4B480E8EE1B8DFF231005E9DC5D8267227684D07A38BA6FECDB288DE53FB0A3E', TRUE,
  'E059080EF4409BC0D96FBCBDDEEE6C0AFBE871AD3D68BBA6A743C64631F599C9', TRUE,
  '26ED148B33F377BA01B68A9A97FEB2391FBED7D51E3F6EB83BEBC2FBA90920B1', TRUE
);

if (!isnull(whitelisted))
{
  thumbprints = list_uniq(split(whitelisted, sep:'\x00', keep:FALSE));
  num_matches = 0;

  foreach thumbprint (thumbprints)
  {
    if (expected_thumbprints[toupper(thumbprint)])
      num_matches++;
  }

  if (num_matches != max_index(keys(expected_thumbprints)))
  {
    if (report_verbosity > 0)
    {
      report =
        '\nIt appears KB2862973 has not been installed since the following' +
        '\nregistry value does not exist and/or does not contain the expected' +
        '\nthumbprints listed in Microsoft KB Article 2862973 :\n\n' +
        'Key : ' + key + '\n' +
        'Name : WeakMd5ThirdPartySha256Allow\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}

audit(AUDIT_HOST_NOT, 'affected');
