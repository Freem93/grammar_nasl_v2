#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88101);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/16 16:23:48 $");

  script_cve_id(
    "CVE-2015-3193",
    "CVE-2015-3194",
    "CVE-2015-3195",
    "CVE-2015-3196",
    "CVE-2015-1794"
  );
  script_bugtraq_id(
    78622,
    78623,
    78626
  );
  script_osvdb_id(
    131037, 
    131038, 
    131039, 
    131040, 
    129459
  );
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151204-openssl");
  script_xref(name:"IAVA", value:"2016-A-0030");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux41420");

  script_name(english:"Mac OS X : Cisco AnyConnect Secure Mobility Client < 3.1.13015.0 / 4.2.x < 4.2.1035.0 Multiple OpenSSL Vulnerabilities");
  script_summary(english:"Checks the version of the Cisco AnyConnect client.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Cisco AnyConnect Secure Mobility Client installed on the remote
Mac OS X host is a version prior to 3.1.13015.0 or 4.2.x prior to
4.2.1035.0. It is, therefore, affected by multiple vulnerabilities in
the bundled version of OpenSSL :
  
  - A carry propagating flaw exists in the x86_64 Montgomery
    squaring implementation that may cause the BN_mod_exp()
    function to produce incorrect results. An attacker can
    exploit this to obtain sensitive information regarding
    private keys. (CVE-2015-3193)

  - A NULL pointer dereference flaw exists in file
    rsa_ameth.c when handling ASN.1 signatures that use the
    RSA PSS algorithm but are missing a mask generation
    function parameter. A remote attacker can exploit this
    to cause the signature verification routine to crash,
    leading to a denial of service. (CVE-2015-3194)

  - A flaw exists in the ASN1_TFLG_COMBINE implementation in
    file tasn_dec.c related to handling malformed
    X509_ATTRIBUTE structures. A remote attacker can exploit
    this to cause a memory leak by triggering a decoding
    failure in a PKCS#7 or CMS application, resulting in a
    denial of service. (CVE-2015-3195)

  - A race condition exists in s3_clnt.c that is triggered
    when PSK identity hints are incorrectly updated in the
    parent SSL_CTX structure when they are received by a
    multi-threaded client. A remote attacker can exploit
    this, via a crafted ServerKeyExchange message, to cause
    a double-free memory error, resulting in a denial of
    service. (CVE-2015-3196)

  - A flaw exists in the ssl3_get_key_exchange() function
    in file s3_clnt.c when handling a ServerKeyExchange
    message for an anonymous DH ciphersuite with the value
    of 'p' set to 0. A attacker can exploit this, by causing
    a segmentation fault, to crash an application linked
    against the library, resulting in a denial of service.
    (CVE-2015-1794)");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151204-openssl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4099a8d6");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCux41420");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20151203.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco AnyConnect Secure Mobility Client version 3.1.13015.0
/ 4.2.1035.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_cisco_anyconnect_installed.nasl");
  script_require_keys("installed_sw/Cisco AnyConnect Secure Mobility Client", "Host/MacOSX/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("Host/MacOSX/Version");

appname = "Cisco AnyConnect Secure Mobility Client";

install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
path = install['path'];
ver  = install['version'];

fix = '';

if (ver =~ "^4\.2\." && (ver_compare(ver:ver, fix:'4.2.1035.0', strict:FALSE) < 0))
  fix = '4.2.1035.0';

else if (ver_compare(ver:ver, fix:'3.1.13015.0', strict:FALSE) < 0)
  fix = '3.1.13015.0';

if (!empty(fix))
{
  if (report_verbosity > 0)
  {
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver, path);
