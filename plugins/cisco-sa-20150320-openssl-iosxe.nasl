#TRUSTED 40455e67d57d04065134f6385acb077fa42967ab700c3d907de3c28efd9d030f0da6d5ce6f678d43421baaab0f317b0e1c04ae7d7d5e5f651c31daa316501afe5e8cd929638737e3a0a40d3816e883027d97e81b54596c295f27b6bc80d92f60265a03183ad8b789329ebd6d908857dfc76b82d30d381963833324faa012392a5dda9827f9fa5828a971f24a60e14f90e39848419d0a3bdff52ec249877c4933101265cadf0bb5f34711659e3edb064f053536f84b157cff6e2a43ced213cb4334bfa3f63a9344cf47582181eb98815c806da9a12b8642f778f3952a4041ea4e288999ab4c191cbc2176d1586f0a51580013c73a321040aaec9bd7ecf638fd8cb5217f827af918681d2dbc4853c16b1e79dd3ccd64c20b867f36cb339d53df4f22ae5852697dc755e7864db44de2e76e8788321b35084611d75b511f43c1d363c5ca5fdfdcea95311f923eea1f8601c4f9b0096325ebb9048c36504a3b75e7772cedb199320aded10ee2db03922ae653fcf9d24da994f3c1b31d7cf293576a1a8862f624053050d8d02b37315787a1253119366ffec74ed7c281db3c2408f133f47174cf30c1bcb2744881a18767af233dd2a2b1664939a12bdecb41f991f5ed9ab0742fb675278117cddf3bb9bf1b7dc72280fc6cf6e940793549a0b4e7472144ca94a897bc28f6f2f99aebdcdb950ab311293f637832e5237934a6555d84c2
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90526);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/14");

  script_cve_id(
    "CVE-2015-0209",
    "CVE-2015-0286",
    "CVE-2015-0287",
    "CVE-2015-0288",
    "CVE-2015-0289",
    "CVE-2015-0292",
    "CVE-2015-0293"
  );
  script_bugtraq_id(
    73225,
    73227,
    73228,
    73231,
    73232,
    73237,
    73239
  );
  script_osvdb_id(
    118817,
    119328,
    119743,
    119755,
    119756,
    119757,
    119761
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCut46130");
  script_xref(name:"CISCO-BUG-ID", value:"CSCut46126");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150320-openssl");

  script_name(english:"Cisco IOS XE Multiple OpenSSL Vulnerabilities (CSCut46130 / CSCut46126)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XE device is missing a vendor-supplied security
patch and has an IOS service configured to use TLS or SSL. It is,
therefore, affected by the following vulnerabilities in the bundled
OpenSSL library :

  - A use-after-free condition exists in the
    d2i_ECPrivateKey() function due to improper processing
    of malformed EC private key files during import. A
    remote attacker can exploit this to dereference or free
    already freed memory, resulting in a denial of service
    or other unspecified impact. (CVE-2015-0209)

  - An invalid read error exists in the ASN1_TYPE_cmp()
    function due to improperly performed boolean-type
    comparisons. A remote attacker can exploit this, via a
    crafted X.509 certificate to an endpoint that uses the
    certificate-verification feature, to cause an invalid
    read operation, resulting in a denial of service.
    (CVE-2015-0286)

  - A flaw exists in the ASN1_item_ex_d2i() function due to
    a failure to reinitialize 'CHOICE' and 'ADB' data
    structures when reusing a structure in ASN.1 parsing.
    This allows a remote attacker to cause an invalid write
    operation and memory corruption, resulting in a denial
    of service. (CVE-2015-0287)

  - A NULL pointer dereference flaw exists in the
    X509_to_X509_REQ() function due to improper processing
    of certificate keys. This allows a remote attacker, via
    a crafted X.509 certificate, to cause a denial of
    service. (CVE-2015-0288)

  - A NULL pointer dereference flaw exists in the PKCS#7
    parsing code due to incorrect handling of missing outer
    ContentInfo. This allows a remote attacker, using an
    application that processes arbitrary PKCS#7 data and
    providing malformed data with ASN.1 encoding, to cause
    a denial of service. (CVE-2015-0289)

  - An integer underflow condition exists in the
    EVP_DecodeUpdate() function due to improper validation
    of base64 encoded input when decoding. This allows a
    remote attacker, using maliciously crafted base64 data,
    to cause a segmentation fault or memory corruption,
    resulting in a denial of service or possibly the
    execution of arbitrary code. (CVE-2015-0292)

  - A flaw exists in servers that both support SSLv2 and
    enable export cipher suites due to improper
    implementation of SSLv2. A remote attacker can exploit
    this, via a crafted CLIENT-MASTER-KEY message, to cause
    a denial of service. (CVE-2015-0293)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150320-openssl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2beef118");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCut46130");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150319.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCut46130.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version  = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
##
# Examines the output of show running config all for evidence
# the WebUI is running and using SSL
#
# @remark 'override' in the return value signals that the scan
#         was not provided sufficient credentials to check for
#         the related configurations. 'flag' signals whether or
#         not the configuration examined shows the webui with
#         SSL is enabled
#
# @return always an array like:
# {
#   'override' : (TRUE|FALSE),
#   'flag'     : (TRUE|FALSE)
# }
##
function iosxe_webui_ssl()
{
  local_var res, buf;
  res = make_array(
    'override',  TRUE,
    'flag',      TRUE
  );

  # Signal we need local checks
  if (!get_kb_item("Host/local_checks_enabled"))
    return res;

  buf = cisco_command_kb_item(
    "Host/Cisco/Config/show_running-config_all",
    "show running-config all"
  );

  # Privilege escalation required
  if (cisco_needs_enable(buf))
    return res;

  res['flag'] = FALSE;

  # Check to make sure no errors in command output
  if(!check_cisco_result(buf))
    return res;

  # All good check for various SSL services
  res['override'] = FALSE;

   # Web UI HTTPS
  if (preg(string:buf, pattern:"^ip http secure-server", multiline:TRUE))
    res['flag'] = TRUE;

  return res;
}

##
# Main check logic
##

flag = 0;
if (version == "3.11.0S") flag++;
if (version == "3.12.0S") flag++;
if (version == "3.13.0S") flag++;
if (version == "3.14.0S") flag++;
if (version == "3.15.0S") flag++;

if (!flag)
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS XE", version);

# Configuration check
sslcheck = iosxe_webui_ssl();

if (!sslcheck['flag'] && !sslcheck['override'])
  audit(AUDIT_HOST_NOT, "affected because it appears the WebUI is not enabled or not using SSL/TLS");

# Override is shown regardless of verbosity
report = "";
if (report_verbosity > 0)
{
  order  = make_list('Cisco bug ID', 'Installed release');
  report = make_array(
    order[0], 'CSCut46130 / CSCut46126',
    order[1], version
  );
  report = report_items_str(report_items:report, ordered_fields:order);
}

security_hole(port:0, extra:report+cisco_caveat(sslcheck['override']));
