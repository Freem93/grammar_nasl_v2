#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76580);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_cve_id(
    "CVE-2010-5298",
    "CVE-2014-0076",
    "CVE-2014-0195",
    "CVE-2014-0198",
    "CVE-2014-0221",
    "CVE-2014-0224",
    "CVE-2014-3470"
  );
  script_bugtraq_id(
    66363,
    66801,
    67193,
    67898,
    67899,
    67900,
    67901
  );
  script_osvdb_id(
    104810,
    105763,
    106531,
    107729,
    107730,
    107731,
    107732
  );
  script_xref(name:"CERT", value:"978508");
  script_xref(name:"IAVA", value:"2014-A-0100");
  script_xref(name:"MCAFEE-SB", value:"SB10075");

  script_name(english:"McAfee VirusScan Enterprise for Linux Multiple OpenSSL Vulnerabilities (SB10075)");
  script_summary(english:"Checks the VSEL version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of McAfee VirusScan Enterprise
for Linux (VSEL) that is affected by multiple vulnerabilities due to
flaws in the included OpenSSL library :

  - An error exists in the function 'ssl3_read_bytes'
    that could allow data to be injected into other
    sessions or allow denial of service attacks. Note
    this issue is only exploitable if
    'SSL_MODE_RELEASE_BUFFERS' is enabled. (CVE-2010-5298)

  - An error exists related to the implementation of the
    Elliptic Curve Digital Signature Algorithm (ECDSA) that
    could allow nonce disclosure via the 'FLUSH+RELOAD'
    cache side-channel attack. (CVE-2014-0076)

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
    clients. (CVE-2014-3470)");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10075");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#CVE-2010-5298");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#CVE-2014-0076");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#CVE-2014-0195");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#CVE-2014-0198");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#CVE-2014-0221");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#CVE-2014-0224");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#CVE-2014-3470");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"see_also", value:"http://ccsinjection.lepidum.co.jp/");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/06/05/earlyccs.html");
  script_set_attribute(attribute:"solution", value:"Apply the relevant hotfix referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:virusscan_enterprise");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_dependencies("mcafee_vsel_detect.nbin");
  script_require_keys("installed_sw/McAfee VirusScan Enterprise for Linux");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "McAfee VirusScan Enterprise for Linux";
get_install_count(app_name:app_name, exit_if_zero:TRUE);

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
hotfixes = install['Hotfixes'];
max_hotfix = int(install['max_hotfix']);
vuln = FALSE;

# Determine fix.
if (version =~ "^1.6\.")
{
  max = "1.6.0.28698";
  hotfix = "HF-961964";
}
else if (version =~ "^1\.7\.1\.")
{
  max = "1.7.1.28698";
  hotfix = "HF-973565";
}
else if (version =~ "^1\.9\.")
{
  max = "1.9.0.28822";
  hotfix = "HF-972024";
}
else if (version =~ "^2\.0\.")
{
  max = "2.0.0.28948";
  hotfix = "HF-967083";
}
else audit(AUDIT_INST_VER_NOT_VULN, version);

if (ver_compare(ver:version, fix:max, strict:FALSE) <= 0)
{
  if (report_paranoia > 1 && !isnull(hotfixes) && hotfix >!< hotfixes) vuln = TRUE;
  else
  {
    hotfix_int = int(hotfix - "HF-");
    if (max_hotfix < hotfix_int) vuln = TRUE;
  }
}

if (vuln)
{
  port = 0;

  if (report_verbosity > 0)
  {
    report = '\n' + app_name + ' ' + version + ' is missing patch ' + hotfix + '.\n';
    security_hole(extra:report, port:port);
  }
  else security_hole(port:port);
  exit(0);
}
else audit(AUDIT_PATCH_INSTALLED, hotfix + " or later");
