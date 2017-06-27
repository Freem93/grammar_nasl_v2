# @DEPRECATED@
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81652);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/07 18:00:12 $");

  script_cve_id("CVE-2015-1637");
  script_bugtraq_id(72965);
  script_osvdb_id(119106);

  script_name(english:"MS KB3046015: Vulnerability in Schannel Could Allow Security Feature Bypass (FREAK)");
  script_summary(english:"The remote host supports a weak set of ciphers.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a security feature bypass
vulnerability, known as FREAK (Factoring attack on RSA-EXPORT Keys),
due to the support of weak EXPORT_RSA cipher suites with keys less
than or equal to 512 bits. A man-in-the-middle attacker may be able to
downgrade the SSL/TLS connection to use EXPORT_RSA cipher suites which
can be factored in a short amount of time, allowing the attacker to
intercept and decrypt the traffic.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/3046015");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");

  script_set_attribute(attribute:"solution", value:
"Apply the recommended workarounds specified by Microsoft.");

  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated","SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

exit(0, "This plugin has been deprecated; use smb_nt_ms15-031.nasl (plugin ID 81745) instead.");

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("byte_func.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');

winver = get_kb_item_or_exit("SMB/WindowsVersion");
report = "";

# For Vista+ Checks
rkey    = "SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\Functions";
ciphers = make_list( # 'Bad' ciphers (in available but not in recommended)
  "TLS_RSA_WITH_AES_128_CBC_SHA",
  "TLS_RSA_WITH_AES_256_CBC_SHA",
  "TLS_RSA_WITH_RC4_128_SHA",
  "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
  "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P521",
  "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P521",
  "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P521",
  "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P521",
  "TLS_RSA_WITH_RC4_128_MD5",
  "SSL_CK_RC4_128_WITH_MD5",
  "SSL_CK_DES_192_EDE3_CBC_WITH_MD5",
  "TLS_RSA_WITH_NULL_SHA",
  "TLS_RSA_WITH_NULL_MD5",
  "TLS_RSA_WITH_AES_128_CBC_SHA256",
  "TLS_RSA_WITH_AES_256_CBC_SHA256",
  "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521",
  "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521",
  "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P521",
  "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P521",
  "TLS_RSA_WITH_NULL_SHA256",
  "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P521",
  "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521"
);

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
if(winver < 6) # Check 2003
{

    report = '\n  The version of windows on the remote system is vulnerable, however'+
             '\n  there is no workaround for the issue at this time\n';
}
else # Vista+
{
  rval = get_registry_value(handle:hklm, item:rkey);
  if(isnull(rval))
  {
    report = '\n'+
             '  The workaround has not been applied; the key \n\n'+
             '    - '+rkey+'\n\n' +
             '  has not been set.\n';
  }
  else
  {
    # Check for bad ciphers
    foreach cipher (ciphers)
    {
      if(cipher >< rval)
        report += '    - '+cipher+'\n';
    }
    if(report!= "")
    {
      report = '\n'+
               '  The following bad ciphers are enabled on the machine :\n\n'+
               report+'\n';
    }
  }
}
RegCloseKey(handle:hklm);
close_registry();

# Workaround applied
if(report == "")
  audit(AUDIT_HOST_NOT, 'affected');

port = kb_smb_transport();
if (report_verbosity > 0)
  security_warning(port:port, extra:report);
else
  security_warning(port);
