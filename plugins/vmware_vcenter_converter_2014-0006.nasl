#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76947);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/08/16 14:42:21 $");

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
  script_xref(name:"IAVB", value:"2014-B-0101");
  script_xref(name:"IAVB", value:"2014-B-0102");
  script_xref(name:"VMSA", value:"2014-0006");

  script_name(english:"VMware vCenter Converter Multiple Vulnerabilities (VMSA-2014-0006)");
  script_summary(english:"Checks the version of VMware vCenter Converter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Converter installed on the remote
Windows host is version 5.1.x prior to 5.1.1 or 5.5.x prior to 5.5.2.
It is, therefore, affected by multiple vulnerabilities in the bundled
OpenSSL library :

  - An error exists in the function 'ssl3_read_bytes'
    that could allow data to be injected into other
    sessions or allow denial of service attacks. Note
    this issue is only exploitable if
    'SSL_MODE_RELEASE_BUFFERS' is enabled. (CVE-2010-5298)

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
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2014-0006.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware vCenter Converter 5.1.1, 5.5.2, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_converter");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_vcenter_converter_installed.nbin");
  script_require_keys("installed_sw/VMware vCenter Converter");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

appname = "VMware vCenter Converter";
get_install_count(app_name:appname, exit_if_zero:TRUE);

# Only 1 install is possible at a time
install = get_installs(app_name:appname);
if (install[0] == IF_NOT_FOUND) audit(AUDIT_NOT_INST, appname);
install = install[1][0];

version = install['version'];
build = install['Build'];
path = install['path'];

if (version =~ '^5\\.1($|\\.)' && ver_compare(ver:version, fix:'5.1.1', strict:FALSE) == -1)
  fixed_version = '5.1.1 Build 1890470';
else if (version =~ '^5\\.5($|\\.)' && ver_compare(ver:version, fix:'5.5.2', strict:FALSE) == -1)
  fixed_version = '5.5.2 Build 1890136';
else 
  audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version + ' Build ' + build +
    '\n  Fixed version     : ' + fixed_version + 
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
