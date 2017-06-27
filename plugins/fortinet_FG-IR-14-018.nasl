#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76493);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/05 16:01:15 $");

  script_cve_id(
    "CVE-2010-5298",
    "CVE-2014-0195",
    "CVE-2014-0221",
    "CVE-2014-0224",
    "CVE-2014-3470"
  );
  script_bugtraq_id(66801, 67900, 67901, 67899, 67898);
  script_osvdb_id(105763, 107729, 107730, 107731, 107732);
  script_xref(name:"CERT", value:"978508");

  script_name(english:"Fortinet OpenSSL Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Fortinet device.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities related to
OpenSSL.");
  script_set_attribute(attribute:"description", value:
"The firmware of the remote Fortinet host is running a version of
OpenSSL that is affected by one or more of the following
vulnerabilities :

  - An error exists in the function 'ssl3_read_bytes'
    that could allow data to be injected into other
    sessions or allow denial of service attacks. Note
    this issue is only exploitable if
    'SSL_MODE_RELEASE_BUFFERS' is enabled. (CVE-2010-5298)

  - A buffer overflow error exists related to invalid DTLS
    fragment handling that could lead to execution of
    arbitrary code. Note this issue only affects OpenSSL
    when used as a DTLS client or server. (CVE-2014-0195)

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
    clients. (CVE-2014-3470)");
  script_set_attribute(attribute:"see_also", value:"http://www.fortiguard.com/advisory/FG-IR-14-018/");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a firmware version containing a fix for this vulnerability
as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:fortinet:fortianalyzer_firmware");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:fortinet:fortimanager_firmware");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:fortinet:fortiweb");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:fortinet:fortimail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version", "Host/Fortigate/build");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

model = get_kb_item_or_exit("Host/Fortigate/model");
version = get_kb_item_or_exit("Host/Fortigate/version");
build = get_kb_item_or_exit("Host/Fortigate/build");

# FortiOS check.
if (preg(string:model, pattern:"forti(gate|wifi)", icase:TRUE))
{
  # Only 4.x and 5.x is affected.
  if (version =~ "^4\.") fix = "4.3.16";
  else if (version =~ "^5\.0\.") fix = "5.0.8";
}
# FortiManager/FortiAnalyzer check, all affected.
if (preg(string:model, pattern:"forti(manager|analyzer)", icase:TRUE))
{
  fix = "5.0.7";
}
# FortiMail Check, all affected.
else if (preg(string:model, pattern:"fortimail", icase:TRUE))
{
  if (version =~ "^5\.1\.") fix = "5.1.3";
  else if (version =~ "^5\.0\.") fix = "5.0.6";
  else fix = "4.3.8";
}
# FortiVoice check, specific models affected.
else if (preg(string:model, pattern:"fortivoice-(200d|2000e|vm)", icase:TRUE))
{
  fix = "3.0.3";
}
# FortiWeb check, all affected.
else if (preg(string:model, pattern:"fortiweb", icase:TRUE))
{
  fix = "5.3.1";
}
# FortiRecorder Check, all affected.
else if (preg(string:model, pattern:"fortirecorder", icase:TRUE))
{
  fix = "1.4.2";
}
# FortiADC, specific models and versions affected.
else if (preg(string:model, pattern:"fortiadc", icase:TRUE))
{
  if (model =~ "E$" && version !~ "^4\.0\.2$") fix = "4.0.3";
}

if (fix && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = 0;
  if (report_verbosity > 0)
  {
    report =
      '\n  Model         : ' + model +
      '\n  Version       : ' + version +
      '\n  Fixed Version : ' + fix +
      '\n';

    security_hole(extra:report, port:port);
  }
  else security_hole(port:port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, model, version);
