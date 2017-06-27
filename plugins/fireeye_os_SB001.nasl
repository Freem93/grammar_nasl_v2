#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77057);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/06/20 20:49:17 $");

  script_cve_id(
    "CVE-2010-5298",
    "CVE-2014-0198",
    "CVE-2014-0221",
    "CVE-2014-0224",
    "CVE-2014-3470"
  );
  script_bugtraq_id(
    66801,
    67193,
    67898,
    67899,
    67901
  );
  script_osvdb_id(
    105763,
    106531,
    107729,
    107731,
    107732,
    125279
  );
  script_xref(name:"CERT", value:"978508");

  script_name(english:"FireEye Operating System Multiple Vulnerabilities (SB001)");
  script_summary(english:"Checks the version of FEOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FireEye Operating System
(FEOS) that is affected by multiple vulnerabilities :

  - An error exists in the function ssl3_read_bytes()
    function that allows data to be injected into other
    sessions or allow denial of service attacks. Note that
    this issue is only exploitable if
    'SSL_MODE_RELEASE_BUFFERS' is enabled. (CVE-2010-5298)

  - An error exists in the do_ssl3_write() function that
    allows a NULL pointer to be dereferenced, leading to
    denial of service attacks. Note that this issue is
    exploitable only if 'SSL_MODE_RELEASE_BUFFERS' is
    enabled. (CVE-2014-0198)

  - An error exists related to DTLS handshake handling that
    allows denial of service attacks. Note that this
    issue only affects OpenSSL when used as a DTLS client.
    (CVE-2014-0221)

  - An unspecified error exists that could allow an
    attacker to cause usage of weak keying material
    leading to simplified man-in-the-middle attacks.
    (CVE-2014-0224)

  - An error exists in the 'dtls1_get_message_fragment'
    function related to anonymous ECDH cipher suites. This
    allows denial of service attacks. Note that this issue
    only affects OpenSSL TLS clients. (CVE-2014-3470)

  - An unspecified flaw exists that allows a remote attacker
    to execute arbitrary commands with root privileges.
    (VulnDB 125279)");
  # http://www.fireeye.com/resources/pdfs/support-notices/security-bulletin-001.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?62e5edf4");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fireeye:feos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("fireeye_os_version.nbin");
  script_require_keys("Host/FireEye/series", "Host/FireEye/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "FireEye OS";
series = get_kb_item_or_exit("Host/FireEye/series");
version = get_kb_item_or_exit("Host/FireEye/version");

if (series == "NX") fix = "7.1.1.222846";
else if (series == "EX") fix = "7.1.1.222846";
else if (series == "FX") fix = "7.1.0.224362";
else if (series == "AX") fix = "7.1.0.223064";
else if (series == "CM")
{
  if (version =~ "^7\.1\.2\.") fix = "7.2.0";
  else fix = "7.1.1.222846";
}
else audit(AUDIT_DEVICE_NOT_VULN, "FireEye "+series);

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = 0;
  if (report_verbosity > 0)
  {
    report =
      '\n  Series            : ' + series +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';

    security_hole(extra:report, port:port);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_DEVICE_NOT_VULN, "FireEye "+series, version);
