#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90508);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/07/25 14:52:53 $");

  script_cve_id(
    "CVE-2015-5370",
    "CVE-2016-2110",
    "CVE-2016-2111",
    "CVE-2016-2112",
    "CVE-2016-2113",
    "CVE-2016-2114",
    "CVE-2016-2115",
    "CVE-2016-2118"
  );
  script_bugtraq_id(86002);
  script_osvdb_id(
    136339,
    136989,
    136990,
    136991,
    136992,
    136993,
    136994,
    136995
  );
  script_xref(name:"CERT", value:"813296");

  script_name(english:"Samba 3.x < 4.2.10 / 4.2.x < 4.2.10 / 4.3.x < 4.3.7 / 4.4.x < 4.4.1 Multiple Vulnerabilities (Badlock)");
  script_summary(english:"Checks the version of Samba.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Samba running on the remote host is 3.x or 4.2.x prior
to 4.2.10, 4.3.x prior to 4.3.7, or 4.4.x prior to 4.4.1. It is,
therefore, affected by multiple vulnerabilities :

  - A flaw exists in the DCE-RPC client when handling
    specially crafted DCE-RPC packets. A man-in-the-middle
    (MitM) attacker can exploit this to downgrade the
    connection security, cause a denial of service through
    resource exhaustion, or potentially execute arbitrary
    code. (CVE-2015-5370)

  - A flaw exists in the implementation of NTLMSSP
    authentication. A MitM attacker can exploit this to
    clear the NTLMSSP_NEGOTIATE_SIGN and
    NTLMSSP_NEGOTIATE_SEAL settings, take over the
    connections, cause traffic to be sent unencrypted, or
    have other unspecified impact. (CVE-2016-2110)

  - A flaw exists in NETLOGON due to a failure to properly
    establish a secure channel connection. A MitM attacker
    can exploit this to spoof the computer names of a secure
    channel's endpoints, potentially gaining session
    information. (CVE-2016-2111)

  - A flaw exists in the integrity protection mechanisms
    that allows a MitM attacker to downgrade a secure LDAP
    connection to an insecure version. (CVE-2016-2112)

  - A flaw exists due to improper validation of TLS
    certificates for the LDAP and HTTP protocols. A MitM
    attacker can exploit this, via a crafted certificate,
    to spoof a server, resulting in the disclosure or
    manipulation of the transmitted traffic. (CVE-2016-2113)

  - A flaw exists due to a failure to enforce the
    'server signing = mandatory' option in smb.conf for
    clients using the SMB1 protocol. A MitM attacker can
    exploit this to conduct spoofing attacks.
    (CVE-2016-2114)

  - A flaw exists due to a failure to perform integrity
    checking for SMB client connections. A MitM attacker can
    exploit this to conduct spoofing attacks since the
    protection mechanisms for DCERPC communication sessions
    are inherited from the underlying SMB connection.
    (CVE-2016-2115)

  - A flaw, known as Badlock, exists in the Security Account
    Manager (SAM) and Local Security Authority
    (Domain Policy) (LSAD) protocols due to improper
    authentication level negotiation over Remote Procedure
    Call (RPC) channels. A MitM attacker who is able to able
    to intercept the traffic between a client and a server
    hosting a SAM database can exploit this flaw to force a
    downgrade of the authentication level, which allows the
    execution of arbitrary Samba network calls in the
    context of the intercepted user, such as viewing or
    modifying sensitive security data in the Active
    Directory (AD) database or disabling critical services.
    (CVE-2016-2118)");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2015-5370.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2016-2110.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2016-2111.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2016-2112.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2016-2113.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2016-2114.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2016-2115.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2016-2118.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-4.2.10.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-4.3.7.html");
  script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/history/samba-4.4.1.html");
  script_set_attribute(attribute:"see_also", value:"http://badlock.org");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.2.10 / 4.3.7 / 4.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

lanman = get_kb_item_or_exit("SMB/NativeLanManager");

if ("Samba " >!< lanman) audit(AUDIT_NOT_LISTEN, "Samba", port);

version = lanman - 'Samba ';

if (version =~ "^4(\.[1-4])?$" || version =~ "^3$")
  audit(AUDIT_VER_NOT_GRANULAR, "Samba", port, version);

fix = NULL;

regexes = make_array(-2, "a(\d+)", -1, "rc(\d+)");

# Affected :
# 3.x.x < 4.2.10
# 4.2.x < 4.2.10
# 4.3.x < 4.3.7
# 4.4.0 < 4.4.1
if (
  version =~ "^3\." ||
  version =~ "^4\.[01]\."
)
  fix = '4.2.10';
if (version =~ "^4\.2\.")
  fix = '4.2.10';
if (version =~ "^4\.3\.")
  fix = '4.3.7';
if (version =~ "^4\.4\.")
  fix = '4.4.1';

if (
  version =~ "^3\." ||
  fix && ver_compare(ver:version, fix:fix, regexes:regexes) < 0
)
{
  report = '\n  Installed version : ' + version +
           '\n  Fixed version     : ' + fix +
           '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra: report);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Samba", port, version);
