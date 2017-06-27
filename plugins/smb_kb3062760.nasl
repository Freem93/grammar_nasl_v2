#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84058);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/09 20:54:58 $");

  script_cve_id(
    "CVE-2014-3572",
    "CVE-2015-0204",
    "CVE-2015-0205"
  );
  script_bugtraq_id(
    71936,
    71941,
    71942
  );
  script_osvdb_id(
    116790,
    116794,
    116795
  );
  script_xref(name:"CERT", value:"243585");

  script_name(english:"MS KB3062760: Update for Vulnerability in Juniper Networks Windows In-Box Junos Pulse Client (FREAK)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has VPN client software installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing KB3062760, which resolves multiple
OpenSSL vulnerabilities in the Juniper Networks Windows In-Box Junos
Pulse client shipped with Windows 8.1 :

  - A flaw exists with ECDH handshakes when using an ECDSA
    certificate without a ServerKeyExchange message. This
    allows a remote attacker to trigger a loss of forward
    secrecy from the ciphersuite. (CVE-2014-3572)

  - A security feature bypass vulnerability, known as FREAK
    (Factoring attack on RSA-EXPORT Keys), exists due to the
    support of weak EXPORT_RSA cipher suites with keys less
    than or equal to 512 bits. A man-in-the-middle attacker
    may be able to downgrade the SSL/TLS connection to use
    EXPORT_RSA cipher suites which can be factored in a
    short amount of time, allowing the attacker to intercept
    and decrypt the traffic. (CVE-2015-0204)

  - A flaw exists when accepting DH certificates for client
    authentication without the CertificateVerify message.
    This allows a remote attacker to authenticate to the
    service without a private key. (CVE-2015-0205)");
  script_set_attribute(attribute:"see_also", value:"https://iam-fed.juniper.net/auth/xlogin.html");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/kb/3062760");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"solution", value:"Install Microsoft KB3062760.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("datetime.inc");
include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

if (hotfix_check_sp_range(win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit('SMB/ProductName');
if ("Windows 8.1" >!< productname ) audit(AUDIT_OS_NOT, "Microsoft Windows 8.1");

arch = get_kb_item_or_exit('SMB/ARCH');

windir = hotfix_get_systemroot();
if (!windir) exit(1, "Failed to get the system root.");

# Check resources.pri
file_name = hotfix_append_path(path:windir, value:"vpnplugins\juniper\resources.pri");
file = hotfix_get_file_contents(path:file_name);

hotfix_handle_error(error_code:file['error'],
                    file:windir + "vpnplugins\juniper\resources.pri",
                    appname:"Junos Pulse VPN Client",
                    exit_on_fail:TRUE);

vuln = FALSE;
if(('\0\0' + unicode(string:"SecondaryTokenPrompt") + '\0\0')       ><  file['data'] &&
   ('\0\0' + unicode(string:"SecondaryOldPasswordPrompt") + '\0\0') >!< file['data'])
  vuln = TRUE;
else audit(AUDIT_HOST_NOT, "affected");

if ( vuln )
{
  port = kb_smb_transport();
  report =
  '\n  File              : ' + file_name +
  '\n  Missing KB update : KB3062760\n';
  security_report_v4(port: port, severity: SECURITY_WARNING, extra: report);
}
