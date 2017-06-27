#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92025);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/08/03 21:01:56 $");

  script_cve_id("CVE-2016-3287");
  script_bugtraq_id(91604);
  script_osvdb_id(141422);
  script_xref(name:"MSFT", value:"MS16-094");
  script_xref(name:"IAVB", value:"2016-B-0112");

  script_name(english:"MS16-094: Security Update for Secure Boot (3177404)");
  script_summary(english:"Checks the version of ci.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by a security bypass vulnerability in the Secure
Boot component due to improperly applying an affected policy. An
attacker who has either administrative privileges or access to the
host can exploit this issue, via installing a crafted policy, to
disable code integrity checks, thus allowing test-signed executables
and drivers to be loaded on the target host. Moreover, the attacker
can exploit this issue to bypass the Secure Boot integrity validation
for BitLocker and the device encryption security features.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-094");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2012, 8.1, RT 8.1,
2012 R2, and 10");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");
include("datetime.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS16-094';
kbs = make_list('3172727', '3163912', '3172985');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
os_version = get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if(hotfix_check_sp_range(win8:'0', win81:'0', win10:'0') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "Windows 8.1" >!< productname)
  audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

function der_parse_set(set,num,list)
{
 local_var tmp, dset, val, i, pos, ret;

 dset = der_decode(data:set);
 if (isnull(dset) || (dset[0] != 0x31))
   return NULL;

 if (!isnull(list) && (list == TRUE))
   return der_parse_list (list:dset[1]);

 tmp = NULL;
 for (i=0; i < num; i++)
   tmp[i] = NULL;

 pos = i = 0;
 while (pos < strlen(dset[1]))
 {
  ret = der_decode(data:dset[1],pos:pos);
  if (isnull(ret))
    return NULL;

  val = ret[0] - 0xA0;
  if (val < 0)
    return NULL;

  tmp[val] = ret[1];
  pos = ret[2];
 }

 return tmp;
}

# Returns Effective Date From STL / CTL
function get_effective_date_from_stl(stl_data)
{
  local_var retval;
  retval = make_array();
  retval['error'] = TRUE;

  local_var OID_PKCS_7_2, OID_CTL, TAG_OBJ, TAG_INT, TAG_UTCTIME, top,
            obj, oid, pkcs, eci, ver, algs, set, i, seq,
            filetime;
  OID_PKCS_7_2 = "1.2.840.113549.1.7.2";
  OID_CTL = "1.3.6.1.4.1.311.10.1";

  TAG_OBJ = 0xA0;
  TAG_INT = 0x02;
  TAG_UTCTIME = 0x30;

  top = der_parse_sequence(seq:stl_data, list:TRUE);
  if (isnull(top))
  {
    retval['value'] = "Failed to parse CTL.";
    return retval;
  }
  if (top[0] < 2)
  {
    retval['value'] = "Too few elements at top level of CTL.";
    return retval;
  }
  oid = der_parse_oid(oid:top[1]);
  if (oid != OID_PKCS_7_2)
  {
    retval['value'] = "OID '" + oid + "' not recognized.";
    return retval;
  }

  obj = der_parse_data(tag:TAG_OBJ, data:top[2]);
  if (isnull(obj))
  {
    retval['value'] = "Failed to parse container.";
    return retval;
  }

  pkcs = der_parse_sequence(seq:obj, list:TRUE);
  if (isnull(pkcs))
  {
    retval['value'] = "Failed to parse PKCS #7 container.";
    return retval;
  }

  if (pkcs[0] < 5)
  {
    retval['value'] = "Too few elements in the PKCS #7 container.";
    return retval;
  }

  # Cryptographic Message Syntax Version
  ver = der_parse_int(i:pkcs[1]);
  if (isnull(ver))
  {
    retval['value'] = "Failed to parse version.";
    return retval;
  }
  if (ver != 1)
  {
    retval['value'] = "No support for version " + ver + ".";
    return retval;
  }

  # Digest Algorithms
  set = der_parse_set(set:pkcs[2], list:TRUE);
  if (isnull(set))
  {
    retval['value'] = "Failed to parse digest algorithms.";
    return retval;
  }
  if (set[0] < 1)
  {
    retval['value'] = "No digest algorithms listed.";
    return retval;
  }

  algs = make_list();
  for (i = 0; i < set[0]; i++)
  {
    algs[i] = der_parse_oid(oid:top[1]);
    if (isnull(algs[i]))
    {
      retval['value'] = "Failed to parse digest algorithm " + i + ".";
      return retval;
    }
  }

  # Encapsulated Content Info
  eci = der_parse_sequence(seq:pkcs[3], list:TRUE);
  if (isnull(pkcs))
  {
    retval['value'] = "Failed to parse Encapsulated Content Info sequence.";
    return retval;
  }
  if (eci[0] < 2)
  {
    retval['value'] = "Too few elements in the Encapsulated Content Info sequence container.";
    return retval;
  }
  oid = der_parse_oid(oid:eci[1]);
  if (oid != OID_CTL)
  {
    retval['value'] = "Encapsulated Content Info OID '" + oid + "' not recognized.";
    return retval;
  }

  obj = der_parse_data(tag:TAG_OBJ, data:eci[2]);
  if (isnull(obj))
  {
    retval['value'] = "Failed to parse undocumented container.";
    return retval;
  }

  eci = der_parse_sequence(seq:obj, list:TRUE);
  if (isnull(eci))
  {
    retval['value'] = "Failed to parse inner Encapsulated Content Info sequence.";
    return retval;
  }
  if (eci[0] < 2)
  {
    retval['value'] = "Too few elements in the inner Encapsulated Content Info sequence container.";
    return retval;
  }

  seq = der_parse_sequence(seq:eci[1], list:TRUE);
  if (isnull(seq))
  {
    retval['value'] = "Failed to parse inner undocumented container.";
    return retval;
  }
  if (seq[0] < 1)
  {
    retval['value'] = "Too few elements in the undocumented container.";
    return retval;
  }

  # States purpose of certs, nothing in Google.
  oid = der_parse_oid(oid:seq[1]);
  if (oid != "1.3.6.1.4.1.311.10.3.30" && oid != "1.3.6.1.4.1.311.61.3.1")
  {
    retval['value'] = "OID '" + oid + "' not recognized.";
    return retval;
  }

  if(oid == "1.3.6.1.4.1.311.61.3.1")
    filetime = substr(eci[2], 2);
  else filetime = der_parse_data(tag:TAG_INT, data:eci[3]);

  if (isnull(filetime))
  {
    retval['value'] = "Failed to parse effective date.";
    return retval;
  }
  retval['error'] = FALSE;
  retval['value'] = filetime;
  return retval;
}

driver_stl_old = FALSE;

# we only need to check Driver.stl on Windows 8 / 8.1 / 2012 R2
if (os_version == "6.2" || os_version == "6.3")
{
  # check effective date in driver.stl
  windir = hotfix_get_systemroot();
  hotfix_check_fversion_init();
  file_path = hotfix_append_path(path:windir, value:"System32\CodeIntegrity\driver.stl");
  driver_stl = hotfix_get_file_contents(path:file_path);

  hotfix_handle_error(error_code:driver_stl['error'], file:file_path, exit_on_fail:TRUE);

  res = get_effective_date_from_stl(stl_data:driver_stl['data']);

  # Effective Date for KB3172727
  # this is the effective date from inside driver.stl
  fix_date_driver_stl = utctime_to_unixtime("160622004707Z");
  cur_date_driver_stl = utctime_to_unixtime(res['value']);

  if (cur_date_driver_stl < fix_date_driver_stl)
  {
    driver_stl_old = TRUE;
    report = '\nThe relevant update does not appear to be installed. This was' +
             '\ndetermined by checking the contents of :\n' +
             '\n' + file_path + '\n';
    hotfix_add_report(bulletin:bulletin, kb:"3172727", report);
  }
}


if (
 # 10 threshold 2 (aka 1511)
  hotfix_is_vulnerable(os:"10", sp:0, file:"ntoskrnl.exe", version:"10.0.10586.494", os_build:"10586", dir:"\system32", bulletin:bulletin, kb:"3172985") ||

  # 10 RTM
  hotfix_is_vulnerable(os:"10", sp:0, file:"ntoskrnl.exe", version:"10.0.10240.17022", os_build:"10240", dir:"\system32", bulletin:bulletin, kb:"3163912") ||

  # Windows Server 2012 / 8.1 / Windows Server 2012 R2
  driver_stl_old
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
