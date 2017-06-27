#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82913);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id(
    "CVE-2014-3569",
    "CVE-2014-3570",
    "CVE-2014-3572",
    "CVE-2014-8275",
    "CVE-2015-0204",
    "CVE-2015-0205"
  );
  script_bugtraq_id(
    71934,
    71935,
    71936,
    71939,
    71941,
    71942
  );
  script_osvdb_id(
    116423,
    116790,
    116792,
    116794,
    116795,
    116796
  );
  script_xref(name:"CERT", value:"243585");

  script_name(english:"Juniper NSM < 2012.2R11 Multiple OpenSSL Vulnerabilities (JSA10679) (FREAK)");
  script_summary(english:"Checks the versions of NSM servers.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of NSM (Network and Security
Manager) Server that is prior to 2012.2R11. It is, therefore, affected
by multiple vulnerabilities related to OpenSSL :

  - A NULL pointer dereference flaw exists when the SSLv3
    option isn't enabled and an SSLv3 ClientHello is
    received. This allows a remote attacker, using an
    unexpected handshake, to crash the daemon, resulting in
    a denial of service. (CVE-2014-3569)

  - The BIGNUM squaring (BN_sqr) implementation does not
    properly calculate the square of a BIGNUM value. This
    allows remote attackers to defeat cryptographic
    protection mechanisms. (CVE-2014-3570)

  - A flaw exists with ECDH handshakes when using an ECDSA
    certificate without a ServerKeyExchange message. This
    allows a remote attacker to trigger a loss of forward
    secrecy from the ciphersuite. (CVE-2014-3572)

  - A flaw exists when accepting non-DER variations of
    certificate signature algorithms and signature encodings
    due to a lack of enforcement of matches between signed
    and unsigned portions. A remote attacker, by including
    crafted data within a certificate's unsigned portion,
    can bypass fingerprint-based certificate-blacklist
    protection mechanisms. (CVE-2014-8275)

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
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10679");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150108.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");

  script_set_attribute(attribute:"solution", value:
"Upgrade to Juniper NSM version 2012.2R11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:network_and_security_manager");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl","juniper_nsm_gui_svr_detect.nasl","juniper_nsm_servers_installed.nasl");
  script_require_keys("Juniper_NSM_VerDetected");
  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");

kb_base = "Host/NSM/";

# No Solaris download available according to the Vendor's advisory
os = get_kb_item("Host/OS");
if (report_paranoia < 2)
{
  if (!isnull(os) && 'Solaris' >< os) audit(AUDIT_HOST_NOT, 'affected');
}

get_kb_item_or_exit("Juniper_NSM_VerDetected");

kb_list = make_list();

temp = get_kb_list("Juniper_NSM_GuiSvr/*/build");

if (!isnull(temp) && max_index(keys(temp)) > 0)
  kb_list = make_list(kb_list, keys(temp));

temp = get_kb_list("Host/NSM/*/build");
if (!isnull(temp) && max_index(keys(temp)) > 0)
  kb_list = make_list(kb_list, keys(temp));

if (max_index(kb_list) == 0) audit(AUDIT_NOT_INST, "Juniper NSM Servers");

report = '';

entry = branch(kb_list);

port = 0;
kb_base = '';

if ("Juniper_NSM_GuiSvr" >< entry)
{
  port = entry - "Juniper_NSM_GuiSvr/" - "/build";
  kb_base = "Juniper_NSM_GuiSvr/" + port + "/";

  report_str1 = "Remote GUI server version : ";
  report_str2 = "Fixed version             : ";
}
else
{
  kb_base = entry - "build";
  if ("guiSvr" >< kb_base)
  {
    report_str1 = "Local GUI server version : ";
    report_str2 = "Fixed version            : ";
  }
  else
  {
    report_str1 = "Local device server version : ";
    report_str2 = "Fixed version               : ";
  }
}

build = get_kb_item_or_exit(entry);
version = get_kb_item_or_exit(kb_base + 'version');

version_disp = version + " (" + build + ")";

# NSM 2012.2R11 or later
# replace r or R with . for easier version comparison
# in 2010 and 2011 versions they use S instead of R
version_num = ereg_replace(pattern:"(r|R|s|S)", replace:".", string:version);

# remove trailing . if it exists
version_num = ereg_replace(pattern:"\.$", replace:"", string:version_num);

fix_disp = "2012.2R11";
fix_num = "2012.2.11";
if (ver_compare(ver:version_num, fix:fix_num, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report = '\n  ' + report_str1 + version_disp +
             '\n  ' + report_str2 + fix_disp +
             '\n';
    security_warning(extra:report, port:port);
  }
  else security_warning(port:port);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Juniper NSM", version_disp);
