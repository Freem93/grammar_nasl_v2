#TRUSTED ae8d25a0b9085dabba881d186d48e17964dc6e531d73324babe29c741fd70ad9ad567e6ac549b8ae300eabf6e95cc2ce8353d0f164dd7d3e60ace12661b2b7d448af7a8e088d4e1f9858cbca10535e280bc38da3e32ca15b5e7f5698f5c6fe741207b43e427fa08ce1d67a46e2b2dfaf1c3e8fdd889d29216cc2d797efb68811b4f430298cdbd95139baadf3a31bd1e59fac438ceb55dcbb46d36d947d4a59b0b32c32c71fcc07a77a738ee0a40093e41a1494cfe2cb69ee6a897f4063b95e8a3381742ce5ff9fa50a700da1f2c67267e1763a2e6e8073321aac049dd572bac1c04eda66def23d56c18b2fcc5067abead60d66551bebee79e161ae948905f05ed5314b3e5796a510995c9a2a85ca9b00e68f3c973ab98a0d6c1cae1c29e6210d1b806a90a5c1fc15db8970a94ed329dc8827cd0eaeb990df7f14aeda6b7727cafaf972dace804754fe25bf3220ac5118a4c07d5ce1236e4c85cb983a7d8c91314c94b00b78600bbfb52c1971cb52e493d6e591be5d67bac381e29077b8a933ea309ac29d728a00663bb7ca8e3863a5e78f05d0c233a98b8cd6b37edf40851d6033e511f70817179d985609f5046e24d687c113c05072cf8d961567b973571437ff7bd7885f4eb63a084f693f9543f1ec586d30535492de12d9ed032e17f0e7ea6dc4d67a1b4c2af00db0e405768c1b344238151d0b6bd055de93b5c5fb92d8dc
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88989);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/03/16");

  script_cve_id(
    "CVE-2010-5298",
    "CVE-2014-0076",
    "CVE-2014-0198",
    "CVE-2014-0224"
  );
  script_bugtraq_id(
    66363,
    66801,
    67193,
    67899
  );
  script_osvdb_id(
    104810,
    105763,
    106531,
    107729
  );
  script_xref(name:"CERT", value:"978508");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup22487");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140605-openssl");

  script_name(english:"Cisco IOS XE Multiple OpenSSL Vulnerabilities (CSCup22487)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XE device is missing a vendor-supplied security
patch, and its web user interface is configured to use HTTPS. It is,
therefore, affected by the following vulnerabilities in the bundled
OpenSSL library :

  - An error exists in the ssl3_read_bytes() function that
    could allow data to be injected into other sessions or
    allow denial of service attacks. Note this issue is only
    exploitable if 'SSL_MODE_RELEASE_BUFFERS' is enabled.
    (CVE-2010-5298)

  - An error exists related to the implementation of the
    Elliptic Curve Digital Signature Algorithm (ECDSA) that
    could allow nonce disclosure via the 'FLUSH+RELOAD'
    cache side-channel attack. (CVE-2014-0076)

  - An error exists in the do_ssl3_write() function that
    could allow a NULL pointer to be dereferenced leading to
    denial of service attacks. Note this issue is
    exploitable only if 'SSL_MODE_RELEASE_BUFFERS' is
    enabled. (CVE-2014-0198)

  - An unspecified error exists that could allow an attacker
    to cause usage of weak keying material leading to
    simplified man-in-the-middle attacks. (CVE-2014-0224)");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140605-openssl#@ID
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d64ee0f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCup22487");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/06/05/earlyccs.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCup22487.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/26");

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
flag     = 0;
override = TRUE;

# Only 3.11.0S, 3.11.1S and 3.12.0S are affected
if (version == "3.11.0S") flag++;
if (version == "3.11.1S") flag++;
if (version == "3.12.0S") flag++;

if (!flag)
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS XE", version);

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item(
    "Host/Cisco/Config/show_running-config_all", "show running-config all");

  if (check_cisco_result(buf))
  {
    override = FALSE;

    if (
      # Web UI HTTPS
      preg(string:buf, pattern:"^ip http secure-server", multiline:TRUE) ||
      # SSL VPN
      cisco_check_sections(
        config:buf,
        section_regex:"^crypto ssl profile ",
        config_regex:'^\\s*no shutdown$'
      ) ||
      # HTTPS client feature / Voice-XML HTTPS client
      preg(string:buf, pattern:"^(ip )?http client secure-", multiline:TRUE) ||
      # CNS feature
      preg(string:buf, pattern:"^cns (config|exec|event) .* encrypt", multiline:TRUE) ||
      # Settlement for Packet Telephony feature
      cisco_check_sections(
        config:buf,
        section_regex:"^settlement ",
        config_regex:make_list('^\\s*url https:', '^\\s*no shutdown$')
      ) ||
      # CMTS billing feature
      preg(string:buf, pattern:"^cable metering .* secure", multiline:TRUE)
    ) flag++;
  }
  else if (cisco_needs_enable(buf))
  {
    flag++;
    override = TRUE;
  }

  if (!flag)
    audit(AUDIT_HOST_NOT, "affected because it does not appear as though any service utilizing the OpenSSL library is enabled");  
}

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : CSCup22487' +
    '\n  Installed release : ' + version +
    '\n';
  security_warning(port:0, extra:report+cisco_caveat(override));
}
else security_warning(port:0, extra:cisco_caveat(override));
