#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76355);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/12 14:59:32 $");

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

  script_name(english:"VMware vSphere Client Multiple Vulnerabilities (VMSA-2014-0006)");
  script_summary(english:"Checks the version of vSphere Client.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization client application installed that
is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of vSphere Client installed on the remote Windows host is
is affected by the following vulnerabilities in the OpenSSL library :

  - An error exists in the function 'ssl3_read_bytes'
    that could allow data to be injected into other
    sessions or allow denial of service attacks. Note
    this issue is only exploitable if
    'SSL_MODE_RELEASE_BUFFERS' is enabled. (CVE-2010-5298)

  - An error exists in the function 'do_ssl3_write' that
    could allow a NULL pointer to be dereferenced leading to
    denial of service attacks. Note this issue is
    exploitable only if 'SSL_MODE_RELEASE_BUFFERS' is
    enabled. (CVE-2014-0198)

  - An unspecified error exists that could allow an
    attacker to cause usage of weak keying material
    leading to simplified man-in-the-middle attacks.
    (CVE-2014-0224)

  - An unspecified error exists related to anonymous ECDH
    ciphersuites that could allow denial of service
    attacks. Note this issue only affects OpenSSL TLS
    clients. (CVE-2014-3470)");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2014-0006.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to vSphere Client 5.0 Update 3a / 5.1 Update 2a / 5.5 Update
1b or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vsphere_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("vsphere_client_installed.nasl");
  script_require_keys("SMB/VMware vSphere Client/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

installs = get_kb_list_or_exit("SMB/VMware vSphere Client/*/Path");

info = '';
unaffected = make_list();
vuln = 0;

foreach version (keys(installs))
{
  path = installs[version];
  version = version - 'SMB/VMware vSphere Client/' - '/Path';
  matches = eregmatch(pattern:'^([0-9\\.]+) build ([0-9]+)$', string:version);
  if (matches)
  {
    ver = matches[1];
    build = matches[2];
  }
  if (ver =~ '^5\\.5\\.0$' && int(build) < 1880841)
  {
    vuln++;
    info +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.5.0 build 1880841\n';
  }
  else if (ver =~ '^5\\.1\\.0$' && int(build) < 1880906)
  {
    vuln++;
    info +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.1.0 build 1880906\n';
  }
  else if (ver =~ '^5\\.0\\.0$' && int(build) < 1917469)
  {
    vuln++;
    info +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.0.0 build 1917469\n';
  }
  else
    unaffected = make_list(unaffected, version);
}

if (vuln)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0) security_warning(port:port, extra:info);
  else security_warning(port);
  exit(0);
}

if (max_index(unaffected) > 0)  audit(AUDIT_INST_VER_NOT_VULN, "VMware vSphere Client", unaffected);
else exit(1, 'Unexpected error - \'unaffected\' is empty.');
