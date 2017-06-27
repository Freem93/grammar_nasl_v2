#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(77004);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/04 18:02:12 $");

  script_cve_id(
    "CVE-2010-5298",
    "CVE-2014-0195",
    "CVE-2014-0198",
    "CVE-2014-0221",
    "CVE-2014-0224",
    "CVE-2014-3470"
  );
  script_bugtraq_id(66801, 67193, 67898, 67899, 67900, 67901);
  script_osvdb_id(105763, 106531, 107729, 107730, 107731, 107732);
  script_xref(name:"CERT", value:"978508");

  script_name(english:"Cerberus FTP Server 6.x < 6.0.10.0 / 7.x < 7.0.0.3 Multiple OpenSSL Vulnerabilities");
  script_summary(english:"Checks the version of the Cerberus FTP Server.");

  script_set_attribute(attribute:"synopsis", value:
"The FTP server installed on the remote Windows host is affected by
multiple OpenSSL vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Cerberus FTP Server on the remote host is version 6.x
prior to 6.0.10.0 or version 7.x prior to 7.0.0.3. It is, therefore,
affected by the following OpenSSL vulnerabilities :

  - An error exists in the 'ssl3_read_bytes' function
    that permits data to be injected into other sessions
    or allows denial of service attacks. Note that this
    issue is exploitable only if SSL_MODE_RELEASE_BUFFERS
    is enabled. (CVE-2010-5298)

  - A buffer overflow error exists related to invalid DTLS
    fragment handling that permits the execution of
    arbitrary code or allows denial of service attacks.
    Note that this issue only affects OpenSSL when used
    as a DTLS client or server. (CVE-2014-0195)

  - An error exists in the 'do_ssl3_write' function that
    permits a NULL pointer to be dereferenced, which could
    allow denial of service attacks. Note that this issue
    is exploitable only if SSL_MODE_RELEASE_BUFFERS is
    enabled. (CVE-2014-0198)

  - An error exists related to DTLS handshake handling that
    could allow denial of service attacks. Note that this
    issue only affects OpenSSL when used as a DTLS client.
    (CVE-2014-0221)

  - An error exists in the processing of ChangeCipherSpec
    messages that allows the usage of weak keying material.
    This permits simplified man-in-the-middle attacks to be
    done. (CVE-2014-0224)

  - An error exists in the 'dtls1_get_message_fragment'
    function related to anonymous ECDH cipher suites. This
    could allow denial of service attacks. Note that this
    issue only affects OpenSSL TLS clients. (CVE-2014-3470)");
  script_set_attribute(attribute:"see_also", value:"http://www.cerberusftp.com/products/releasenotes.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cerberus FTP Server 6.0.10.0 / 7.0.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cerberusftp:ftp_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("cerberus_ftp_installed.nasl");
  script_require_keys("SMB/CerberusFTP/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/CerberusFTP/Installed");
installs = get_kb_list_or_exit("SMB/CerberusFTP/*/version");

kb_entry = branch(keys(installs));
kb_base = kb_entry - "/version";

ver  = get_kb_item_or_exit(kb_entry);
file_name = get_kb_item_or_exit(kb_base + "/file");

kb_pieces = split(kb_base, sep:"/");
file = kb_pieces[2] + "\" + file_name;

if (ver =~ "^7\." && ver_compare(ver:ver, fix:'7.0.0.3', strict:FALSE) < 0)
  fix = '7.0.0.3';
else if (ver =~ "^6\." && ver_compare(ver:ver, fix:'6.0.10.0', strict:FALSE) < 0)
  fix = '6.0.10.0';
else audit(AUDIT_INST_PATH_NOT_VULN, "Cerberus FTP Server", ver, file);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (report_verbosity > 0)
{
  report =
    '\n  File              : ' + file +
    '\n  Installed version : ' + ver  +
    '\n  Fixed version     : ' + fix  +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
