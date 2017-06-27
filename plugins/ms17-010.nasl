#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97833);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/05/23 20:13:54 $");

  script_cve_id(
    "CVE-2017-0143",
    "CVE-2017-0144",
    "CVE-2017-0145",
    "CVE-2017-0146",
    "CVE-2017-0147",
    "CVE-2017-0148"
  );
  script_bugtraq_id(
    96703,
    96704,
    96705,
    96706,
    96707,
    96709
  );
  script_osvdb_id(
    153673,
    153674,
    153675,
    153676,
    153677,
    153678,
    155620,
    155634,
    155635
  );
  script_xref(name:"EDB-ID", value:"41891");
  script_xref(name:"EDB-ID", value:"41987");
  script_xref(name:"MSFT", value:"MS17-010");
  script_xref(name:"IAVA", value:"2017-A-0065");

  script_name(english:"MS17-010: Security Update for Microsoft Windows SMB Server (4013389) (ETERNALBLUE) (ETERNALCHAMPION) (ETERNALROMANCE) (ETERNALSYNERGY) (WannaCry) (EternalRocks) (uncredentialed check)");
  script_summary(english:"Checks the presence of MS17-010.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by the following vulnerabilities :

  - Multiple remote code execution vulnerabilities exist in
    Microsoft Server Message Block 1.0 (SMBv1) due to
    improper handling of certain requests. An
    unauthenticated, remote attacker can exploit these
    vulnerabilities, via a specially crafted packet, to
    execute arbitrary code. (CVE-2017-0143, CVE-2017-0144,
    CVE-2017-0145, CVE-2017-0146, CVE-2017-0148)

  - An information disclosure vulnerability exists in
    Microsoft Server Message Block 1.0 (SMBv1) due to
    improper handling of certain requests. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted packet, to disclose sensitive
    information. (CVE-2017-0147)

ETERNALBLUE, ETERNALCHAMPION, ETERNALROMANCE, and ETERNALSYNERGY are
four of multiple Equation Group vulnerabilities and exploits disclosed
on 2017/04/14 by a group known as the Shadow Brokers. WannaCry /
WannaCrypt is a ransomware program utilizing the ETERNALBLUE exploit,
and EternalRocks is a worm that utilizes seven Equation Group
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS17-010");
  # https://blogs.technet.microsoft.com/msrc/2017/04/14/protecting-customers-and-evaluating-risk/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?321523eb");
  # https://blogs.technet.microsoft.com/mmpc/2017/05/12/wannacrypt-ransomware-worm-targets-out-of-date-systems/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7bec1941");
  # https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d9f569cf");
  script_set_attribute(attribute:"see_also", value:"https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/kb/2696547");
  # https://www.us-cert.gov/ncas/current-activity/2017/01/16/SMB-Security-Best-Practices
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8dcab5e4");
  # http://www.theregister.co.uk/2017/01/18/uscert_warns_admins_to_kill_smb_after_shadow_brokers_dump/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?36fd3072");
  # https://www.riskbasedsecurity.com/2016/08/the-shadow-brokers-lifting-the-shadows-of-the-nsas-equation-group/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c7e0cf3");
  script_set_attribute(attribute:"see_also", value:"https://github.com/stamparm/EternalRocks/");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, 10, and 2016. Microsoft has also
released emergency patches for Windows operating systems that are no
longer supported, including Windows XP, 2003, and 8.

For unsupported Windows operating systems, e.g. Windows XP, Microsoft
recommends that users discontinue the use of SMBv1. SMBv1 lacks
security features that were included in later SMB versions. SMBv1 can
be disabled by following the vendor instructions provided in Microsoft
KB2696547. Additionally, US-CERT recommends that users block SMB
directly by blocking TCP port 445 on all network boundary devices. For
SMB over the NetBIOS API, block TCP ports 137 / 139 and UDP ports 137
/ 138 on all network boundary devices.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl", "smb_v1_enabled_remote.nasl");
  script_require_keys("Host/OS", "SMB/SMBv1_is_supported");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("byte_func.inc");
include("global_settings.inc");
include("smb_func.inc");

function smb_get_error_code (data)
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


function my_smb_trans_and_x (setup, transname, param, data, max_pcount, max_dcount)
{
 local_var header, parameters, dat, packet, ret, pad1, trans, p_offset, d_offset, plen, dlen, slen, pad2, npad;

 npad = pad1 = pad2 = NULL;

 if (session_is_unicode () == 1)
  trans = cstring (string:transname);
 else
  trans = transname;

 header = smb_header (Command: SMB_COM_TRANSACTION,
                      Status: nt_status (Status: STATUS_SUCCESS));

 p_offset = 32 + 1 + 28 + strlen(setup) + 2 + strlen(trans);

 # Unicode transname should be aligned to 2 byte 
 if(session_is_unicode() == 1)
 {
  npad = crap(data:'\x00', length: (2 - p_offset % 2) % 2);
  p_offset += strlen(npad);
 }

 # Parameter is aligned to 4 byte
 pad1 = crap(data:'\x00', length: (4 - p_offset % 4) % 4);
 p_offset += strlen(pad1);

 # Data is aligned to 4 byte
 d_offset = p_offset + strlen (param);
 pad2 = crap(data:'\x00', length: (4 - d_offset % 4) % 4);
 d_offset += strlen(pad2);

 plen = strlen(param);
 dlen = strlen(data);
 slen = strlen(setup);

 if(isnull(max_pcount)) max_pcount =0xffff;
 if(isnull(max_dcount)) max_dcount =0xffff;

 parameters = 
        raw_word (w:plen)       +   # total parameter count
	      raw_word (w:dlen)       +   # total data count
	      raw_word (w:max_pcount) +   # Max parameter count
	      raw_word (w:max_dcount) +   # Max data count
	      raw_byte (b:0)          +   # Max setup count
        raw_byte (b:0)          +   # Reserved
	      raw_word (w:0)          +   # Flags
	      raw_dword (d:0)         +   # Timeout
	      raw_word (w:0)          +   # Reserved
	      raw_word (w:plen)       +   # Parameter count
	      raw_word (w:p_offset)   +   # Parameter offset
	      raw_word (w:dlen)       +   # Data count
	      raw_word (w:d_offset)   +   # Data offset
	      raw_byte (b:slen/2)     +   # Setup count
	      raw_byte (b:0);             # Reserved

 parameters += setup;

 parameters = smb_parameters (data:parameters);

 dat = npad +
       trans +
       pad1 +
       param +
       pad2 +
       data;

 dat = smb_data (data:dat);

 packet = netbios_packet (header:header, parameters:parameters, data:dat);

 ret = smb_sendrecv (data:packet);
 if (!ret)
   return NULL;

 return smb_get_error_code (data:ret);
}


#
# MAIN
#

# Make sure it's Windows 
os = get_kb_item_or_exit("Host/OS");
if ("Windows" >!< os)
  audit(AUDIT_HOST_NOT, "Windows"); 
  
# Make sure SMBv1 is enabled
if (! get_kb_item("SMB/SMBv1_is_supported"))
  exit(0, "SMB version 1 does not appear to be enabled on the remote host."); 

if (!smb_session_init(smb2:FALSE)) audit(AUDIT_FN_FAIL, 'smb_session_init');

r = NetUseAdd(share:"IPC$");
if (r != 1)
{
  exit(1, 'Failed to connect to the IPC$ share anonymously.');
}

fid = 0; # Invalid FID 
setup = raw_word (w:0x23) + raw_word (w:fid);  

status = my_smb_trans_and_x (setup: setup, transname:"\PIPE\");
NetUseDel();

if(! isnull(status))
{
  if(status == STATUS_INVALID_HANDLE
    ||  status == STATUS_ACCESS_DENIED # Win 10
  )
  {
    audit(AUDIT_HOST_NOT , "affected"); 
  }
  else if (status == STATUS_INSUFF_SERVER_RESOURCES)
  {
    port = kb_smb_transport();
    security_report_v4(port: port, severity: SECURITY_HOLE);
  }
  else
  {
    status = "0x" + toupper(hexstr(mkdword(status)));
    audit(AUDIT_RESP_BAD, port, "an SMB_COM_TRANSACTION request. Status code: " + status);
  }
}
else
{
  exit(1, "Failed to get response status for an SMB_COM_TRANSACTION request."); 
}
