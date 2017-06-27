#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76579);
  script_version("$Revision: 1.10 $");
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
  script_xref(name:"MCAFEE-SB", value:"SB10075");

  script_name(english:"McAfee Email Gateway OpenSSL Multiple Vulnerabilities (SB10075)");
  script_summary(english:"Checks the MEG version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities related to the
included OpenSSL library.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of McAfee Email Gateway (MEG)
that is affected by the multiple vulnerabilities related to the
included OpenSSL library :

  - An error exists in the function 'ssl3_read_bytes' that
    can allow data to be injected into other sessions or
    allow denial of service attacks. Note that this issue is
    exploitable only if 'SSL_MODE_RELEASE_BUFFERS' is
    enabled. (CVE-2010-5298)

  - An error exists related to the implementation of the
    Elliptic Curve Digital Signature Algorithm (ECDSA) that
    can allow nonce disclosure via the 'FLUSH+RELOAD' cache
    side-channel attack. (CVE-2014-0076)

  - A buffer overflow error exists related to invalid DTLS
    fragment handling that can lead to execution of
    arbitrary code. Note that this issue only affects
    OpenSSL when used as a DTLS client or server.
    (CVE-2014-0195)

  - An error exists in the function 'do_ssl3_write' that
    can allow a NULL pointer to be dereferenced leading
    to denial of service attacks. Note that this issue is
    exploitable only if 'SSL_MODE_RELEASE_BUFFERS' is
    enabled. (CVE-2014-0198)

  - An error exists related to DTLS handshake handling that
    can lead to denial of service attacks. Note that this
    issue only affects OpenSSL when used as a DTLS client.
    (CVE-2014-0221)

  - An unspecified error exists that can allow an attacker
    to cause usage of weak keying material leading to
    simplified man-in-the-middle attacks. (CVE-2014-0224)

  - An unspecified error exists related to anonymous ECDH
    cipher suites that can allow denial of service attacks.
    Note that this issue only affects OpenSSL TLS clients.
    (CVE-2014-3470)");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10075");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"solution", value:"Apply the relevant hotfix referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:email_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_dependencies("mcafee_email_gateway_version.nbin");
  script_require_keys("Host/McAfeeSMG/name", "Host/McAfeeSMG/version", "Host/McAfeeSMG/patches");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = get_kb_item_or_exit("Host/McAfeeSMG/name");
version = get_kb_item_or_exit("Host/McAfeeSMG/version");
patches = get_kb_item_or_exit("Host/McAfeeSMG/patches");

# Determine fix.
if (version =~ "^5\.6\.")
{
  fix = "5.6.2964.107";
  hotfix = "5.6h973308";
}
else if (version =~ "^7\.0\.")
{
  fix = "7.0.2934.109";
  hotfix = "7.0.5h973323";
}
else if (version =~ "^7\.5\.")
{
  fix = "7.5.2846.121";
  hotfix = "7.5h968383";
}
else if (version =~ "^7\.6\.")
{
  fix = "7.6.3044.102";
  hotfix = "7.6h968406";
}
else audit(AUDIT_INST_VER_NOT_VULN, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1 && hotfix >!< patches)
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
else audit(AUDIT_PATCH_INSTALLED, hotfix);
