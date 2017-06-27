#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77389);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/04/25 14:31:38 $");

  script_cve_id(
    "CVE-2010-5298",
    "CVE-2014-0198",
    "CVE-2014-0224",
    "CVE-2014-3470"
  );
  script_bugtraq_id(66801, 67193, 67898, 67899);
  script_osvdb_id(105763, 106531, 107729, 107731);
  script_xref(name:"CERT", value:"978508");
  script_xref(name:"VMSA", value:"2014-0006");

  script_name(english:"Pivotal Web Server 5.x < 5.4.1 Multiple OpenSSL Vulnerabilities");
  script_summary(english:"Checks the version in the server response header.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server has an application installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Pivotal Web Server (formerly VMware vFabric Web Server)
installed on the remote host is version 5.x prior to 5.4.1. It is,
therefore, affected by multiple vulnerabilities in the bundled version
of OpenSSL :

  - An error exists in the 'ssl3_read_bytes' function
    that permits data to be injected into other sessions
    or allows denial of service attacks. Note that this
    issue is exploitable only if SSL_MODE_RELEASE_BUFFERS
    is enabled. (CVE-2010-5298)

  - An error exists in the 'do_ssl3_write' function that
    permits a null pointer to be dereferenced, which could
    allow denial of service attacks. Note that this issue
    is exploitable only if SSL_MODE_RELEASE_BUFFERS is
    enabled. (CVE-2014-0198)

  - An error exists in the processing of ChangeCipherSpec
    messages that allows the usage of weak keying material.
    This permits simplified man-in-the-middle attacks to be
    done. (CVE-2014-0224)

  - An error exists in the 'dtls1_get_message_fragment'
    function related to anonymous ECDH cipher suites. This
    could allow denial of service attacks. Note that this
    issue only affects OpenSSL TLS clients. (CVE-2014-3470)

Note that Nessus did not actually test for these issues, but has
instead relied on the version in the server's banner.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2014-0006.html");
  # Patch ( vmware.com ) download
  # https://my.vmware.com/web/vmware/details?downloadGroup=VF_530_PVTL_WSVR_541&productId=335&rPId=6214
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80b8e207");
  # Advisory ( pivotal.io )
  script_set_attribute(attribute:"see_also", value:"http://www.pivotal.io/security/CVE-2014-0224");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 5.4.1 / 6.0 or later.

Alternatively, apply the vendor patch and restart the service.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vfabric_web_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pivotal:pivotal_web_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("pivotal_webserver_version.nbin");
  script_require_keys("installed_sw/Pivotal Web Server", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_name = "Pivotal Web Server";
get_install_count(app_name:app_name, exit_if_zero:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

install = get_single_install(app_name:app_name, port:port);
version = install['version'];
source  = install['Source'];

if (version !~ "^5\.") audit(AUDIT_NOT_LISTEN, app_name + " 5.x", port);

# Affected :
# vFabric Web Server 5.0.x, 5.1.x, 5.2.x, 5.3.x
# Pivotal Web Server 5.4.0
if (
  # 5.x < 5.4
  version =~ "^5\.[0-3]($|[^0-9])"
  ||
  # 5.4.x < 5.4.1
  version =~ "^5\.4\.0($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.4.1 / 6.0\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
