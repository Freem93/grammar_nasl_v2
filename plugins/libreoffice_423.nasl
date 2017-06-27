#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76510);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_cve_id(
    "CVE-2010-5298",
    "CVE-2013-4353",
    "CVE-2013-6449",
    "CVE-2013-6450",
    "CVE-2014-0160",
    "CVE-2014-0195",
    "CVE-2014-0198",
    "CVE-2014-0221",
    "CVE-2014-0224",
    "CVE-2014-3470"
  );
  script_bugtraq_id(
    64530,
    64618,
    64691,
    66690,
    66801,
    67193,
    67898,
    67899,
    67900,
    67901
  );
  script_osvdb_id(
    101347,
    101597,
    101843,
    105465,
    105763,
    106531,
    107729,
    107730,
    107731,
    107732
  );
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"CERT", value:"978508");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");

  script_name(english:"LibreOffice 4.2.x < 4.2.3 OpenSSL Multiple Vulnerabilities (Heartbleed)");
  script_summary(english:"Checks version of LibreOffice.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"A version of LibreOffice 4.2.x prior to 4.2.3 is installed on the
remote Windows host. This version of LibreOffice is bundled with a
version of OpenSSL affected by multiple vulnerabilities :

  - An error exists in the function 'ssl3_read_bytes'
    that could allow data to be injected into other
    sessions or allow denial of service attacks. Note
    this issue is only exploitable if
    'SSL_MODE_RELEASE_BUFFERS' is enabled. (CVE-2010-5298)

  - An error exists in the 'ssl3_take_mac' function in the
    file 'ssl/s3_both.c' related to handling TLS handshake
    traffic that could lead to denial of service attacks.
    (CVE-2013-4353)

  - An error exists in the 'ssl_get_algorithm2' function in
    the file 'ssl/s3_lib.c' related to handling TLS 1.2
    traffic that could lead to denial of service attacks.
    (CVE-2013-6449)

  - An error exists related to the handling of DTLS
    retransmission processes that could lead to denial of
    service attacks. (CVE-2013-6450)

  - An out-of-bounds read error, known as the 'Heartbleed
    Bug', exists related to handling TLS heartbeat
    extensions that could allow an attacker to obtain
    sensitive information such as primary key material,
    secondary key material, and other protected content.
    (CVE-2014-0160)

  - A buffer overflow error exists related to invalid DTLS
    fragment handling that could lead to execution of
    arbitrary code. Note this issue only affects OpenSSL
    when used as a DTLS client or server. (CVE-2014-0195)

  - An error exists in the function 'do_ssl3_write' that
    could allow a NULL pointer to be dereferenced leading
    to denial of service attacks. Note this issue is
    exploitable only if 'SSL_MODE_RELEASE_BUFFERS' is
    enabled. (CVE-2014-0198)

  - An error exists related to DTLS handshake handling that
    could lead to denial of service attacks. Note this
    issue only affects OpenSSL when used as a DTLS client.
    (CVE-2014-0221)

  - An unspecified error exists that could allow an
    attacker to cause usage of weak keying material
    leading to simplified man-in-the-middle attacks.
    (CVE-2014-0224)

  - An unspecified error exists related to anonymous ECDH
    cipher suites that could allow denial of service
    attacks. Note this issue only affects OpenSSL TLS
    clients. (CVE-2014-3470)

Note that Nessus has not attempted to exploit these issues, but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"solution", value:"Upgrade to LibreOffice version 4.2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"see_also", value:"http://www.libreoffice.org/about-us/security/advisories/cve-2014-0160/");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("libreoffice_installed.nasl");
  script_require_keys("SMB/LibreOffice/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = "SMB/LibreOffice";
version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);
version_ui = get_kb_item_or_exit(kb_base+"/Version_UI", exit_code:1);

# Versions 4.2 up to and not including 4.2.3 are vulnerable.
if (version =~ "^4\.2($|\.[0-2]($|[^0-9]))")
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_ui +
      '\n  Fixed version     : 4.2.3' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "LibreOffice", version_ui, path);
