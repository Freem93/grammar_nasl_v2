#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76145);
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
  script_bugtraq_id(66363, 66801, 67193, 67898, 67899, 67900, 67901);
  script_osvdb_id(104810, 105763, 106531, 107729, 107730, 107731, 107732);
  script_xref(name:"CERT", value:"978508");
  script_xref(name:"MCAFEE-SB", value:"SB10075");

  script_name(english:"McAfee ePolicy Orchestrator Multiple OpenSSL Vulnerabilities (SB10075)");
  script_summary(english:"Checks version of OpenSSL installed with ePolicy Orchestrator.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of McAfee ePolicy Orchestrator
that is affected by multiple vulnerabilities due to flaws in the
OpenSSL library :

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
    ciphersuites that could allow denial of service
    attacks. Note this issue only affects OpenSSL TLS
    clients. (CVE-2014-3470))");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10075");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=PD25233");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#CVE-2010-5298");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#2014-0076");
  # script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#CVE-2014-0195");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#CVE-2014-0198");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#CVE-2014-0221");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#CVE-2014-0224");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#CVE-2014-3470");
  script_set_attribute(attribute:"solution", value:"Apply Hotfix 973112 as per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_epo_installed.nasl");
  script_require_keys("SMB/mcafee_epo/Path", "SMB/mcafee_epo/ver");
  script_require_ports("SMB/transport", 139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

app_name = "McAfee ePolicy Orchestrator";
version = get_kb_item_or_exit("SMB/mcafee_epo/ver");
install_path = get_kb_item_or_exit("SMB/mcafee_epo/Path");

hotfix = 'Hotfix 973112';
hotfix_file = "Apache2\bin\ssleay32.dll";
hotfix_fversion = "1.0.1.8";
min_affected = "0.9.8";

# for FIPS detection
java_security_file = "JRE\lib\security\java.security";
FIPS_enabled_pattern = "^\ *orion.fips140.mode\ *=\ *true";

# Versions 4.6, 5.0 and 5.1 are affected.
if (version !~ "^4\.6\." && version !~ "^5\.[01]\.") audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, install_path);

# If it is configured to run in FIPS mode, it is not vuln
java_security_path = hotfix_append_path(path:install_path, value:java_security_file);
if (hotfix_file_exists(path:java_security_path))
{
  data = hotfix_get_file_contents(java_security_path);
  hotfix_handle_error(error_code:data["error"], file:java_security_path, appname:app_name, exit_on_fail:TRUE);
  data = data["data"];
  if (egrep(pattern:FIPS_enabled_pattern, string:data))
  {
    hotfix_check_fversion_end();
    audit(AUDIT_INST_PATH_NOT_VULN, app_name, version + " running in FIPS 140-2 mode", install_path);
  }
}

# Check the version of the affected DLL.
dll_path = hotfix_append_path(path:install_path, value:hotfix_file);
dll_version = hotfix_get_fversion(path:dll_path);
hotfix_handle_error(error_code:dll_version['error'], file:dll_path, appname:app_name, exit_on_fail:TRUE);
hotfix_check_fversion_end();

dll_version = join(dll_version['value'], sep:'.');

if (ver_compare(ver:dll_version, fix:min_affected, strict:FALSE) == -1) audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, install_path);

if (ver_compare(ver:dll_version, fix:hotfix_fversion, strict:FALSE) == -1)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + install_path +
      '\n  Installed version : ' + version +
      '\n  OpenSSL DLL       : ' + dll_path +
      '\n  DLL version       : ' + dll_version +
      '\n  Fixed version     : ' + hotfix_fversion +
      '\n  ' +
      '\n' + 'Note: The install may not be vulnerable to all of the CVEs' +
      '\n' + '      listed; however, applying the hotfix will ensure coverage' +
      '\n' + '      of all CVEs.' +
      '\n';
    security_hole(extra:report, port:port);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_PATCH_INSTALLED, hotfix);
