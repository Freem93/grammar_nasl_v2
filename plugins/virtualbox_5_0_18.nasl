#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90680);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/16 16:21:31 $");

  script_cve_id(
    "CVE-2015-1794",
    "CVE-2015-3193",
    "CVE-2015-3194",
    "CVE-2015-3195",
    "CVE-2015-3196",
    "CVE-2015-3197",
    "CVE-2016-0678"
  );
  script_bugtraq_id(
    78622,
    78623,
    78626,
    82237
  );
  script_osvdb_id(
    129459,
    131037,
    131038,
    131039,
    131040,
    133715,
    137317
  );
  script_xref(name:"CERT", value:"257823");

  script_name(english:"Oracle VM VirtualBox < 4.3.36 / 5.0.18 Multiple Vulnerabilities (April 2016 CPU)");
  script_summary(english:"Performs a version check on VirtualBox.exe.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Oracle VM VirtualBox application installed on the remote host is a
version prior to 4.3.36 or 5.0.18. It is, therefore, affected by an
unspecified flaw in the Core subcomponent that allows a local attacker
to gain elevated privileges. Additionally, multiple vulnerabilities
exist in the bundled version of OpenSSL :

  - A flaw exists in the ssl3_get_key_exchange() function
    in file s3_clnt.c when handling a ServerKeyExchange
    message for an anonymous DH ciphersuite with the value
    of 'p' set to 0. A attacker can exploit this, by causing
    a segmentation fault, to crash an application linked
    against the library, resulting in a denial of service.
    (CVE-2015-1794)

  - A carry propagating flaw exists in the x86_64 Montgomery
    squaring implementation that may cause the BN_mod_exp()
    function to produce incorrect results. An attacker can
    exploit this to obtain sensitive information regarding
    private keys. (CVE-2015-3193)

  - A NULL pointer dereference flaw exists in file
    rsa_ameth.c due to improper handling of ASN.1 signatures
    that are missing the PSS parameter. A remote attacker
    can exploit this to cause the signature verification
    routine to crash, resulting in a denial of service
    condition. (CVE-2015-3194)

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

  - A cipher algorithm downgrade vulnerability exists due to
    a flaw that is triggered when handling cipher
    negotiation. A remote attacker can exploit this to
    negotiate SSLv2 ciphers and complete SSLv2 handshakes
    even if all SSLv2 ciphers have been disabled on the
    server. Note that this vulnerability only exists if the
    SSL_OP_NO_SSLv2 option has not been disabled.
    (CVE-2015-3197)");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?855180af");
  script_set_attribute(attribute:"see_also", value:"https://www.virtualbox.org/wiki/Changelog");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle VM VirtualBox version 4.3.36 / 5.0.18 or later as
referenced in the April 2016 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("virtualbox_installed.nasl", "macosx_virtualbox_installed.nbin");
  script_require_ports("installed_sw/Oracle VM VirtualBox", "installed_sw/VirtualBox");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app  = NULL;
apps = make_list('Oracle VM VirtualBox', 'VirtualBox');

foreach app (apps)
{
  if (get_install_count(app_name:app)) break;
  else app = NULL;
}

if (isnull(app)) audit(AUDIT_NOT_INST, 'Oracle VM VirtualBox');

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

ver  = install['version'];
path = install['path'];

# Affected :
# 4.3.x < 4.3.36
# 5.0.x < 5.0.18
if       (ver =~ '^4\\.3' && ver_compare(ver:ver, fix:'4.3.36', strict:FALSE) < 0) fix = '4.3.36';
else if  (ver =~ '^5\\.0' && ver_compare(ver:ver, fix:'5.0.18', strict:FALSE) < 0) fix = '5.0.18';
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);

port = 0;
if (app == 'Oracle VM VirtualBox')
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;
}

report =
  '\n  Path              : ' + path +
  '\n  Installed version : ' + ver +
  '\n  Fixed version     : ' + fix +
  '\n';
security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
exit(0);
