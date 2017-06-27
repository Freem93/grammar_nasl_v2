#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77150);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/21 22:04:46 $");

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
    66801,
    66363,
    67900,
    67193,
    67901,
    67899,
    67898
  );
  script_osvdb_id(
    105763,
    104810,
    107730,
    106531,
    107732,
    107729,
    107731
  );
  script_xref(name:"CERT", value:"978508"); #CVE-2014-0224
  script_xref(name:"HP",value:"SSRT101614");
  script_xref(name:"HP",value:"HPSBMU03057");
  script_xref(name:"HP",value:"emr_na-c04349897");

  script_name(english:"HP Version Control Agent (VCA) < 7.3.3 Multiple SSL Vulnerabilities");
  script_summary(english:"Checks the version of VCA installed.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains software that is affected by multiple
vulnerabilities related to SSL.");
  script_set_attribute(attribute:"description", value:
"The installation of HP Version Control Agent (VCA) on the remote
Windows host is a version prior to 7.3.3. It is, therefore, affected
by multiple vulnerabilities in the bundled version of SSL :

  - An error exists in the 'ssl3_read_bytes' function
    that permits data to be injected into other sessions
    or allows denial of service attacks. Note that this
    issue is exploitable only if SSL_MODE_RELEASE_BUFFERS
    is enabled. (CVE-2010-5298)

  - A flaw in the ECDS Algorithm implementation can
    be triggered using a FLUSH+RELOAD cache side-channel
    attack which may allow a malicious process to recover
    ECDSA nonces. (CVE-2014-0076)

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
  script_set_attribute(attribute:"solution", value:"Upgrade to VCA 7.3.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  # https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04349897-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0e53fea");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/532577/30/0/threaded");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:version_control_agent");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_version_control_agent_installed.nbin");
  script_require_keys("installed_sw/HP Version Control Agent");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "HP Version Control Agent";
get_install_count(app_name:app,exit_if_zero:TRUE);
install = get_single_install(app_name:app);
version = install["version"];
path    = install["path"];
fix     = "7.3.3.0";

# Unknown version
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_APP_VER,app);

if (ver_compare(ver:version,fix:fix,strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port,extra:report);
  }
  else security_hole(port:port);
}
else audit(AUDIT_INST_PATH_NOT_VULN,app,version,path);
