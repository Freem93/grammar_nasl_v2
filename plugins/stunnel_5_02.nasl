#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74421);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/07/29 16:23:47 $");

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

  script_name(english:"stunnel < 5.02 OpenSSL Multiple Vulnerabilities");
  script_summary(english:"Checks version of stunnel.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a program that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of stunnel installed on the remote host is prior to
version 5.02. It is, therefore, affected by the following
vulnerabilities :

  - An error exists in the ssl3_read_bytes() function that
    allows data to be injected into other sessions or allows
    denial of service attacks. Note this issue is only
    exploitable if 'SSL_MODE_RELEASE_BUFFERS' is enabled.
    (CVE-2010-5298)

  - A buffer overflow error exists related to invalid DTLS
    fragment handling that allows an attacker to execute
    arbitrary code. Note this issue only affects OpenSSL
    when used as a DTLS client or server. (CVE-2014-0195)

  - An error exists in the do_ssl3_write() function that
    allows a NULL pointer to be dereferenced, resulting in a
    denial of service condition. Note this issue is
    exploitable only if 'SSL_MODE_RELEASE_BUFFERS' is
    enabled. (CVE-2014-0198)

  - An error exists related to DTLS handshake handling that
    could lead to denial of service attacks. Note this
    issue only affects OpenSSL when used as a DTLS client.
    (CVE-2014-0221)

  - An unspecified error exists that allows an attacker to
    cause usage of weak keying material, resulting in
    simplified man-in-the-middle attacks. (CVE-2014-0224)

  - An unspecified error exists related to anonymous ECDH
    ciphersuites that allows an attacker to cause a denial
    of service condition. Note this issue only affects
    OpenSSL TLS clients. (CVE-2014-3470)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://stunnel.org/?page=sdf_ChangeLog");
  # https://www.stunnel.org/pipermail/stunnel-announce/2014-June/000077.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6ba4dbbe");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to stunnel version 5.02 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:stunnel:stunnel");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("stunnel_installed.nasl");
  script_require_keys("installed_sw/stunnel");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'stunnel';
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

version = install["version"];
path = install["path"];

# Affected < 5.02
if (
  version =~ "^[0-4]($|[^0-9])" ||
  version =~ "^5\.0[01]($|[^0-9])"
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 5.02\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
