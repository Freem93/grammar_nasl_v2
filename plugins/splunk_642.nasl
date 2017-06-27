#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92790);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id(
    "CVE-2013-0211",
    "CVE-2015-2304",
    "CVE-2016-1541",
    "CVE-2016-2107"
  );
  script_bugtraq_id(
    58926,
    89355,
    89760,
    92183,
    92184
  );
  script_osvdb_id(
    92680,
    117148,
    134334,
    137896,
    142260,
    142261
  );
  script_xref(name:"CERT", value:"862384");
  script_xref(name:"EDB-ID", value:"39768");

  script_name(english:"Splunk Enterprise < 5.0.16 / 6.0.12 / 6.1.11 / 6.2.11 / 6.3.6 / 6.4.2 or Splunk Light < 6.4.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Splunk Enterprise and Light.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Splunk
Enterprise hosted on the remote web server is 5.0.x, 6.0.x prior to
6.0.12, 6.1.x prior to 6.1.11, 6.2.x prior to 6.2.11, 6.3.x prior to
6.3.6, or 6.4.x prior to 6.4.2; or else it is Splunk Light version
6.4.x prior to 6.4.2. It is, therefore, affected by the following
vulnerabilities :

  - An integer signedness error exists in libarchive in the
    archive_write_zip_data() function within file
    archive_write_set_format_zip.c due to improper
    conversion between unsigned and signed integer types
    when running on 64-bit CPUs. An unauthenticated, remote
    attacker can exploit this to cause a buffer overflow,
    resulting in a denial of service condition.
    (CVE-2013-0211)

  - A path traversal vulnerability exists in libarchive in
    the bsdcpio() function within file in cpio/cpio.c due to
    improper sanitization of user-supplied input. An
    unauthenticated, remote attacker can exploit this, via
    a specially crafted path in an archive, to write to
    arbitrary files. (CVE-2015-2304)

  - A heap-based buffer overflow condition exists in
    libarchive in the zip_read_mac_metadata() function
    within file archive_read_support_format_zip.c due to
    improper sanitization of user-supplied input. An
    unauthenticated, remote attacker can exploit this, via
    specially crafted entry-size values in a ZIP archive, to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2016-1541)

  - Multiple flaws exist in the OpenSSL library in the
    aesni_cbc_hmac_sha1_cipher() function in file
    crypto/evp/e_aes_cbc_hmac_sha1.c and the
    aesni_cbc_hmac_sha256_cipher() function in file
    crypto/evp/e_aes_cbc_hmac_sha256.c that are triggered
    when the connection uses an AES-CBC cipher and AES-NI
    is supported by the server. A man-in-the-middle attacker
    can exploit these to conduct a padding oracle attack,
    resulting in the ability to decrypt the network traffic.
    (CVE-2016-2107)

  - An unspecified cross-site scripting (XSS) vulnerability
    exists due to improper validation of user-supplied
    input. An unauthenticated, remote attacker can exploit
    this, via a specially crafted request, to execute
    arbitrary script code in the user's browser session.
    (VulnDB 142260)

  - An unspecified cross-site redirection vulnerability
    exists due to improper validation of user-supplied
    input. An unauthenticated, remote attacker can exploit
    this, by convincing a user to visit a specially crafted
    web link, to redirect the browser to an arbitrary
    website of the attacker's own choosing. (VulnDB 142261)

Note that Splunk Enterprise 5.0.x will not be patched for OpenSSL
issues, and it is recommended you upgrade to the latest version.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.splunk.com/view/SP-CAAAPQM");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160503.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade Splunk Enterprise to version 6.0.12 / 6.1.11 / 6.2.11 /
6.3.6 / 6.4.2 or later, or Splunk Light to version 6.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libarchive:libarchive");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("splunkd_detect.nasl", "splunk_web_detect.nasl");
  script_require_ports("Services/www", 8089, 8000);
  script_require_keys("installed_sw/Splunk");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Splunk";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8000, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
ver = install['version'];
license = install['License'];
fix = FALSE;

install_url = build_url(qs:dir, port:port);

note = NULL;
if (license == "Enterprise")
{
  # 5.0.x < 5.0.16
  # Splunk Enterprise 5.0.x will not be patched for OpenSSL issues.
  # Splunk recommends updating to the latest version of Splunk Enterprise.
  if (ver =~ "^5\.0($|[^0-9])")
    fix = '6.4.2';

  # 6.0.x < 6.0.12
  else if (ver =~ "^6\.0($|[^0-9])")
    fix = '6.0.12';

  # 6.1.x < 6.1.11
  else if (ver =~ "^6\.1($|[^0-9])")
    fix = '6.1.11';

  # 6.2.x < 6.2.11
  else if (ver =~ "^6\.2($|[^0-9])")
    fix = '6.2.11';

  # 6.3.x < 6.3.6
  else if (ver =~ "^6\.3($|[^0-9])")
    fix = '6.3.6';

  # 6.4.x < 6.4.2
  else if (ver =~ "^6\.4($|[^0-9])")
    fix = '6.4.2';
}
else if (license == "Light")
{
  # any < 6.4.2
  fix = '6.4.2';
}

if (fix && ver_compare(ver:ver,fix:fix,strict:FALSE) < 0)
{
  order = make_list("URL", "Installed version", "Fixed version");
  report = make_array(
    order[0], install_url,
    order[1], ver + " " + license,
    order[2], fix + " " + license
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING, xss:TRUE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, ver + " " + license);
