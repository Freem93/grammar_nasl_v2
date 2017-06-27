#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91427);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/06/02 14:01:16 $");

  script_cve_id(
    "CVE-2014-8176",
    "CVE-2015-1788",
    "CVE-2015-1789",
    "CVE-2015-1790",
    "CVE-2015-1791",
    "CVE-2015-1792",
    "CVE-2015-1798",
    "CVE-2015-1799",
    "CVE-2015-4000",
    "CVE-2015-4595"
  );
  script_bugtraq_id(
    73950,
    73951,
    74733,
    75154,
    75156,
    75157,
    75158,
    75159,
    75161
  );
  script_osvdb_id(
    120350,
    120351,
    122331,
    122875,
    123172,
    123173,
    123174,
    123175,
    123176,
    137400
  );
  script_xref(name:"CERT", value:"374268");
  script_xref(name:"CISCO-BUG-ID", value:"CSCut83796");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu82343");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv33150");

  script_name(english:"Cisco ACE 4710 Appliance / ACE30 Module Multiple Vulnerabilities (Logjam)");
  script_summary(english:"Checks the ACE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Cisco Application Control Engine (ACE) software installed on the
remote Cisco ACE 4710 device or ACE30 module is version A5 prior to
A5(3.3). It is, therefore, affected by multiple vulnerabilities :

  - An invalid free memory error exists due to improper
    validation of user-supplied input when a DTLS peer
    receives application data between ChangeCipherSpec and
    Finished messages. A remote attacker can exploit this to
    corrupt memory, resulting in a denial of service or
    the execution of arbitrary code. (CVE-2014-8176)

  - A denial of service vulnerability exists when processing
    an ECParameters structure due to an infinite loop that
    occurs when a specified curve is over a malformed binary
    polynomial field. A remote attacker can exploit this to
    perform a denial of service against any system that
    processes public keys, certificate requests, or
    certificates. This includes TLS clients and TLS servers
    with client authentication enabled. (CVE-2015-1788)

  - A denial of service vulnerability exists due to improper
    validation of the content and length of the ASN1_TIME
    string by the X509_cmp_time() function. A remote
    attacker can exploit this, via a malformed certificate
    and CRLs of various sizes, to cause a segmentation
    fault, resulting in a denial of service condition. TLS
    clients that verify CRLs are affected. TLS clients and
    servers with client authentication enabled may be
    affected if they use custom verification callbacks.
    (CVE-2015-1789)

  - A NULL pointer dereference flaw exists in the PKCS#7
    parsing code due to incorrect handling of missing inner
    'EncryptedContent'. This allows a remote attacker, via
    specially crafted ASN.1-encoded PKCS#7 blobs with
    missing content, to cause a denial of service condition
    or other potential unspecified impacts. (CVE-2015-1790)

  - A double-free error exists due to a race condition that
    occurs when a NewSessionTicket is received by a
    multi-threaded client when attempting to reuse a
    previous ticket. A remote attacker can exploit this to
    cause a denial of service condition or other potential
    unspecified impact. (CVE-2015-1791)

  - A denial of service vulnerability exists in the CMS code
    due to an infinite loop that occurs when verifying a
    signedData message. A remote attacker can exploit this
    to cause a denial of service condition. (CVE-2015-1792)

  - The symmetric-key feature in the receive function
    requires a correct message authentication code (MAC)
    only if the MAC field has a nonzero length. This makes
    it easier for a man-in-the-middle attacker to spoof
    packets by omitting the MAC. (CVE-2015-1798)

  - A flaw exists in the symmetric-key feature in the
    receive function when handling a specially crafted
    packet sent to one of two hosts that are peering with
    each other. This allows an attacker to cause the next
    attempt by the servers to synchronize to fail.
    (CVE-2015-1799)

  - A man-in-the-middle vulnerability, known as Logjam,
    exists due to a flaw in the SSL/TLS protocol. A remote
    attacker can exploit this flaw to downgrade connections
    using ephemeral Diffie-Hellman key exchange to 512-bit
    export-grade cryptography. (CVE-2015-4000)

  - A flaw exists in the TLS 1.x implementation in the
    Cavium SDK due to a failure to check the first byte of
    the padding bytes. A man-in-the-middle attacker can
    exploit this, by sending specially crafted requests to
    the server, to induce requests that allow determining
    the plaintext chunks of data. This vulnerability is a
    variant of the POODLE attack. (CVE-2015-4595)");
  # https://www.cisco.com/c/en/us/td/docs/app_ntwk_services/data_center_app_services/ace_appliances/VA5_3_x/release/note/ACE_app_rn_A53x.html#pgfId-947807
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8bf8fa00");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCut83796");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuu82343");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuv33150");
  # https://vivaldi.net/en-US/userblogs/entry/there-are-more-poodles-in-the-forest
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f38496c");
  script_set_attribute(attribute:"see_also", value:"https://weakdh.org/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco ACE version A5(3.3) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:application_control_engine_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ace_version.nasl");
  script_require_keys("Host/Cisco/ACE/Version", "Host/Cisco/ACE/Model");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/Cisco/ACE/Version");
model   = get_kb_item_or_exit("Host/Cisco/ACE/Model");

if (model != "4710" && model != "ACE30") audit(AUDIT_DEVICE_NOT_VULN, "Cisco ACE " + model);

if (
  version =~ "^A[34][^0-9]" ||
  version =~ "^A5\([0-2][^0-9]" ||
  version =~ "^A5\(3(\.[0-2][a-z]*)?\)"
)
{
  report = '\n  Installed version : ' + version +
           '\n  Fixed version     : A5(3.3)' +
           '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ACE", version);
