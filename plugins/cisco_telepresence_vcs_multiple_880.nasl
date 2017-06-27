#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92045);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/08/08 14:39:33 $");

  script_cve_id(
    "CVE-2015-2808",
    "CVE-2015-6413",
    "CVE-2016-1444",
    "CVE-2016-2105",
    "CVE-2016-2106",
    "CVE-2016-2107",
    "CVE-2016-2108",
    "CVE-2016-2109",
    "CVE-2016-2176"
  );
  script_bugtraq_id(
    73684,
    79088,
    87940,
    89744,
    89746,
    89752,
    89757,
    89760,
    91669
  );
  script_osvdb_id(
    117855,
    131485,
    137577,
    137896,
    137897,
    137898,
    137899,
    137900,
    141156
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw54155");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz55590");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw55636");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw55651");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz64601");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160504-openssl");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160706-vcs");
  script_xref(name:"EDB-ID", value:"39768");

  script_name(english:"Cisco TelePresence VCS / Expressway 8.x < 8.8 Multiple Vulnerabilities (Bar Mitzvah)");
  script_summary(english:"Checks the software version.");

  script_set_attribute(attribute:"synopsis", value:
"A video conferencing application running on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco TelePresence Video
Communication Server (VCS) / Expressway running on the remote host is
8.x prior to 8.8. It is, therefore, affected by multiple
vulnerabilities :

  - A security feature bypass vulnerability exists, known as
    Bar Mitzvah, due to improper combination of state data
    with key data by the RC4 cipher algorithm during the
    initialization phase. A man-in-the-middle attacker can
    exploit this, via a brute-force attack using LSB values,
    to decrypt the traffic. (CVE-2015-2808)

  - A flaw exists in the web framework of TelePresence Video
    Communication Server (VCS) Expressway due to missing
    authorization checks on certain administrative pages. An
    authenticated, remote attacker can exploit this to
    bypass read-only restrictions and install Tandberg Linux
    Packages (TLPs) without proper authorization.
    (CVE-2015-6413)

  - A flaw exists in certificate management and validation
    for the Mobile and Remote Access (MRA) component due to
    improper input validation of a trusted certificate. An
    unauthenticated, remote attacker can exploit this, using
    a trusted certificate, to bypass authentication and gain
    access to internal HTTP system resources.
    (CVE-2016-1444)

  - A heap buffer overflow condition exists in the
    EVP_EncodeUpdate() function within file
    crypto/evp/encode.c that is triggered when handling
    a large amount of input data. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition. (CVE-2016-2105)

  - A heap buffer overflow condition exists in the
    EVP_EncryptUpdate() function within file
    crypto/evp/evp_enc.c that is triggered when handling a
    large amount of input data after a previous call occurs
    to the same function with a partial block. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (CVE-2016-2106)

  - Multiple flaws exist in the aesni_cbc_hmac_sha1_cipher()
    function in file crypto/evp/e_aes_cbc_hmac_sha1.c and
    the aesni_cbc_hmac_sha256_cipher() function in file
    crypto/evp/e_aes_cbc_hmac_sha256.c that are triggered
    when the connection uses an AES-CBC cipher and AES-NI
    is supported by the server. A man-in-the-middle attacker
    can exploit these to conduct a padding oracle attack,
    resulting in the ability to decrypt the network traffic.
    (CVE-2016-2107)

  - A remote code execution vulnerability exists in the
    ASN.1 encoder due to an underflow condition that occurs
    when attempting to encode the value zero represented as
    a negative integer. An unauthenticated, remote attacker
    can exploit this to corrupt memory, resulting in the
    execution of arbitrary code. (CVE-2016-2108)

  - Multiple unspecified flaws exist in the d2i BIO
    functions when reading ASN.1 data from a BIO due to
    invalid encoding causing a large allocation of memory.
    An unauthenticated, remote attacker can exploit these to
    cause a denial of service condition through resource
    exhaustion. (CVE-2016-2109)

  - An out-of-bounds read error exists in the
    X509_NAME_oneline() function within file
    crypto/x509/x509_obj.c when handling very long ASN.1
    strings. An unauthenticated, remote attacker can exploit
    this to disclose the contents of stack memory.
    (CVE-2016-2176)

  - An information disclosure vulnerability exists in the
    file system permissions due to certain files having
    overly permissive permissions. An unauthenticated, local
    attacker can exploit this to disclose sensitive
    information. (Cisco bug ID CSCuw55636)

Note that Cisco bug ID CSCuw55636 and CVE-2015-6413 only affect
versions 8.6.x prior to 8.8.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160706-vcs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e3d5088");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160504-openssl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4146a30f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuw54155");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuz55590");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuw55636");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuw55651");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuz64601");
  # https://www.blackhat.com/docs/asia-15/materials/asia-15-Mantin-Bar-Mitzvah-Attack-Breaking-SSL-With-13-Year-Old-RC4-Weakness-wp.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4bbf45ac");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco TelePresence VCS / Expressway version 8.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server_software");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_video_communication_server_detect.nbin");
  script_require_keys("Cisco/TelePresence_VCS/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version  = get_kb_item_or_exit("Cisco/TelePresence_VCS/Version");
fullname = "Cisco TelePresence Device";

if (version =~ "^8\.[0-7]($|[^0-9])")
{
  report = '\n  Installed version : ' + version +
           '\n  Fixed version     : 8.8' +
           '\n';
  security_report_v4(severity:SECURITY_HOLE,port:0, extra:report);
}
else audit(AUDIT_DEVICE_NOT_VULN, fullname, version);
