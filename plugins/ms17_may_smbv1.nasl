#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100464);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/26 23:47:03 $");

  script_cve_id(
    "CVE-2017-0267",
    "CVE-2017-0268",
    "CVE-2017-0269",
    "CVE-2017-0270",
    "CVE-2017-0271",
    "CVE-2017-0272",
    "CVE-2017-0273",
    "CVE-2017-0274",
    "CVE-2017-0275",
    "CVE-2017-0276",
    "CVE-2017-0277",
    "CVE-2017-0278",
    "CVE-2017-0279",
    "CVE-2017-0280"
   );
  script_bugtraq_id(
    98259,
    98260,
    98261,
    98263,
    98264,
    98265,
    98266,
    98267,
    98268,
    98270,
    98271,
    98272,
    98273,
    98274
  );
  script_osvdb_id(
    157230,
    157231,
    157232,
    157233,
    157234,
    157235,
    157236,
    157237,
    157238,
    157239,
    157240,
    157246,
    157247,
    157248
  );
  script_xref(name:"MSKB", value:"4016871");
  script_xref(name:"MSKB", value:"4018466");
  script_xref(name:"MSKB", value:"4019213");
  script_xref(name:"MSKB", value:"4019214");
  script_xref(name:"MSKB", value:"4019215");
  script_xref(name:"MSKB", value:"4019216");
  script_xref(name:"MSKB", value:"4019263");
  script_xref(name:"MSKB", value:"4019264");
  script_xref(name:"MSKB", value:"4019472");
  script_xref(name:"MSKB", value:"4019473");
  script_xref(name:"MSKB", value:"4019474");

  script_name(english:"Microsoft Windows SMBv1 Multiple Vulnerabilities");
  script_summary(english:"Checks the response from the SMBv1 server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has Microsoft Server Message Block 1.0 (SMBv1)
enabled. It is, therefore, affected by multiple vulnerabilities :

  - Multiple information disclosure vulnerabilities exist
    in Microsoft Server Message Block 1.0 (SMBv1) due to
    improper handling of SMBv1 packets. An unauthenticated,
    remote attacker can exploit these vulnerabilities, via a
    specially crafted SMBv1 packet, to disclose sensitive
    information. (CVE-2017-0267, CVE-2017-0268,
    CVE-2017-0270, CVE-2017-0271, CVE-2017-0274,
    CVE-2017-0275, CVE-2017-0276)

  - Multiple denial of service vulnerabilities exist in
    Microsoft Server Message Block 1.0 (SMBv1) due to
    improper handling of requests. An unauthenticated,
    remote attacker can exploit these vulnerabilities, via a
    specially crafted SMB request, to cause the system to
    stop responding. (CVE-2017-0269, CVE-2017-0273,
    CVE-2017-0280)

  - Multiple remote code execution vulnerabilities exist in
    Microsoft Server Message Block 1.0 (SMBv1) due to
    improper handling of SMBv1 packets. An unauthenticated,
    remote attacker can exploit these vulnerabilities, via a
    specially crafted SMBv1 packet, to execute arbitrary
    code. (CVE-2017-0272, CVE-2017-0277, CVE-2017-0278,
    CVE-2017-0279)

Depending on the host's security policy configuration, this plugin
cannot always correctly determine if the Windows host is vulnerable if
the host is running a later Windows version (i.e., Windows 8.1, 10,
2012, 2012 R2, and 2016) specifically that named pipes and shares are
allowed to be accessed remotely and anonymously. Tenable does not
recommend this configuration, and the hosts should be checked locally
for patches with one of the following plugins, depending on the
Windows version : 100054, 100055, 100057, 100059, 100060, or 100061.");
# https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0267
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c21268d4");
# https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0268
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9253982");
# https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0269
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?23802c83");
# https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0270
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8313bb60");
# https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0271
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7677c678");
# https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0272
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?36da236c");
# https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0273
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0981b934");
# https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0274
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c88efefa");
# https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0275
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?695bf5cc");
# https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0276
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?459a1e8c");
# https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0277
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea45bbc5");
# https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0278
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4195776a");
# https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0279
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fbf092cf");
# https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0280
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c0cc566");
  script_set_attribute(attribute:"solution", value:
"Apply the applicable security update for your Windows version :

  - Windows Server 2008     : KB4018466
  - Windows 7               : KB4019264
  - Windows Server 2008 R2  : KB4019264
  - Windows Server 2012     : KB4019216
  - Windows 8.1 / RT 8.1.   : KB4019215
  - Windows Server 2012 R2  : KB4019215
  - Windows 10              : KB4019474
  - Windows 10 Version 1511 : KB4019473
  - Windows 10 Version 1607 : KB4019472
  - Windows 10 Version 1703 : KB4016871
  - Windows Server 2016     : KB4019472");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_family(english:"Windows");
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

function my_smb_trans2(setup, param, plen, data, max_pcount, max_dcount, max_scount)
{
 local_var header, parameters, dat, packet, ret, pad1, p_offset, d_offset, dlen, slen, pad2; 

 pad1 = pad2 = NULL;

 header = smb_header (Command: SMB_COM_TRANSACTION2,
                      Status: nt_status (Status: STATUS_SUCCESS));

 p_offset = 32 + 1 + 28 + strlen(setup) + 2 + 1;

 # Parameter is aligned to 4 byte
 pad1 = crap(data:'\x00', length: (4 - p_offset % 4) % 4);
 p_offset += strlen(pad1);

 # Data is aligned to 4 byte
 d_offset = p_offset + strlen (param);
 pad2 = crap(data:'\x00', length: (4 - d_offset % 4) % 4);
 d_offset += strlen(pad2);

 if(isnull(plen)) plen = strlen(param); 
 dlen = strlen(data);
 slen = strlen(setup);

 if(slen % 2) return NULL; 

 if(isnull(max_pcount)) max_pcount = 0x1000;
 if(isnull(max_dcount)) max_dcount = 0x1000;
 if(isnull(max_scount)) max_scount = 0x20;

 parameters = 
        raw_word (w:plen)         +   # total parameter count
	      raw_word (w:dlen)         +   # total data count
	      raw_word (w:max_pcount)   +   # Max parameter count
	      raw_word (w:max_dcount)   +   # Max data count
	      raw_byte (b:max_scount)   +   # Max setup count
        raw_byte (b:0)            +   # Reserved1
	      raw_word (w:0)            +   # Flags
	      raw_dword (d:0)           +   # Timeout
	      raw_word (w:0)            +   # Reserved2
	      raw_word (w:plen)         +   # Parameter count
	      raw_word (w:p_offset)     +   # Parameter offset
	      raw_word (w:dlen)         +   # Data count
	      raw_word (w:d_offset)     +   # Data offset
	      raw_byte (b:slen/2)       +   # Setup count
	      raw_byte (b:0);               # Reserved3

 parameters += setup;

 parameters = smb_parameters (data:parameters);

 dat = '\x00' + # Name  
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

setup = raw_word(w:0x06);  
param = raw_word(w:0xbeef) + raw_dword(d:0);   
status = my_smb_trans2(setup: setup, data: NULL, param:param);
NetUseDel();

if(! isnull(status))
{
  if(status == 0x00000001) 
  {
    audit(AUDIT_HOST_NOT , "affected"); 
  }
  else if (status == STATUS_NOT_SUPPORTED)
  {
    port = kb_smb_transport();
    security_report_v4(port: port, severity: SECURITY_HOLE);
  }
  else
  {
    port = kb_smb_transport();
    status = "0x" + toupper(hexstr(mkdword(status)));
    audit(AUDIT_RESP_BAD, port, "an SMB_COM_TRANSACTION2 request. Status code: " + status);
  }
}
else
{
  exit(1, "Failed to get response status for an SMB_COM_TRANSACTION2 request. Possibly 'NullSessionPipes' and 'NullSessionShares' are not configured on the server."); 
}
