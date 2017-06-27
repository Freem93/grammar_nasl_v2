#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76769);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/21 22:04:46 $");

  script_cve_id(
    "CVE-2010-5298",
    "CVE-2014-0195",
    "CVE-2014-0198",
    "CVE-2014-0221",
    "CVE-2014-0224",
    "CVE-2014-2608",
    "CVE-2014-3470"
  );
  script_bugtraq_id(
    66801,
    67193,
    67898,
    67899,
    67900,
    67901,
    71613
  );
  script_osvdb_id(
    105763,
    106531,
    107729,
    107730,
    107731,
    107732,
    115650
  );
  script_xref(name:"CERT", value:"978508");
  script_xref(name:"HP", value:"emr_na-c04349175");
  script_xref(name:"HP", value:"HPSBMU03055");
  script_xref(name:"HP", value:"SSRT101616");
  script_xref(name:"HP", value:"emr_na-c04302476");
  script_xref(name:"HP", value:"HPSBMU03043");
  script_xref(name:"HP", value:"SSRT101578");

  script_name(english:"HP Smart Update Manager 6.x < 6.4.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of HP Smart Update Manager.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running software that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of HP Smart Update manager running on the remote host is
prior to 6.4.1. It is, therefore, affected by the following
vulnerabilities :

  - An error exists in the function 'ssl3_read_bytes' that
    can allow data to be injected into other sessions or
    allow denial of service attacks. Note that this issue is
    exploitable only if 'SSL_MODE_RELEASE_BUFFERS' is
    enabled. (CVE-2010-5298)

  - A buffer overflow error exists related to invalid DTLS
    fragment handling that can lead to the execution of
    arbitrary code. Note that this issue only affects
    OpenSSL when used as a DTLS client or server.
    (CVE-2014-0195)

  - An error exists in the function 'do_ssl3_write' that
    can allow a NULL pointer to be dereferenced leading to
    denial of service attacks. Note that this issue is
    exploitable only if 'SSL_MODE_RELEASE_BUFFERS' is
    enabled. (CVE-2014-0198)

  - An error exists related to DTLS handshake handling that
    can lead to denial of service attacks. Note that this
    issue only affects OpenSSL when used as a DTLS client.
    (CVE-2014-0221)

  - An unspecified error exists in how ChangeCipherSpec
    messages are processed that can allow an attacker to
    cause usage of weak keying material, leading to
    simplified man-in-the-middle attacks. (CVE-2014-0224)

  - An unspecified flaw exists that allows a local attacker
    to disclose sensitive information. Note that if the host
    OS is Linux based, only versions 6.2.0, 6.3.0, 6.3.1,
    and 6.4.0 suffer from this flaw. (CVE-2014-2608)

  - An unspecified error exists related to anonymous ECDH
    cipher suites that can allow denial of service attacks.
    Note that this issue only affects OpenSSL TLS clients.
    (CVE-2014-3470)");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04349175
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f782b0f");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04302476
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?de20bd57");
  script_set_attribute(attribute:"solution", value:"Upgrade to HP Smart Update Manager 6.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:smart_update_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_sum_detect.nbin");
  script_require_keys("installed_sw/HP Smart Update Manager");
  script_require_ports("Services/www", 63001, 63002);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

appname = "HP Smart Update Manager";
get_install_count(app_name:appname, exit_if_zero:TRUE);

# service may be marked as broken, so don't use get_http_port
port = get_kb_item("Services/www");
if (!port) port = 63001;

install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);

version = install['version'];
install_url = build_url(port:port, qs:install['path']);

# 6.0.0 to 6.4.0 vulnerable
if (
  ver_compare(ver:version, fix:"6.0.0", strict:FALSE) >= 0 &&
  ver_compare(ver:version, fix:"6.4.1", strict:FALSE) == -1
)
{
  if (report_verbosity > 0)
  {
    report = '\n  URL               : ' + install_url +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : 6.4.1' +
             '\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url);
