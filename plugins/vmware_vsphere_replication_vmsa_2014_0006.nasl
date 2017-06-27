#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78024);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/06/03 21:04:42 $");

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

  script_name(english:"VMware vSphere Replication Multiple OpenSSL Vulnerabilities (VMSA-2014-0006)");
  script_summary(english:"Checks the version of vSphere Replication.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization appliance installed that is
affected by multiple OpenSSL vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The VMware vSphere Replication installed on the remote host is version
5.5.x prior to 5.5.1.1, or else it is version 5.6.x. It is, therefore,
affected by the following OpenSSL related vulnerabilities :

  - An error exists in the function 'ssl3_read_bytes' that
    could allow data to be injected into other sessions or
    allow denial of service attacks. Note that this issue
    is exploitable only if 'SSL_MODE_RELEASE_BUFFERS' is
    enabled. (CVE-2010-5298)

  - An error exists in the function 'do_ssl3_write' that
    could allow a NULL pointer to be dereferenced leading to
    denial of service attacks. Note that this issue is
    exploitable only if 'SSL_MODE_RELEASE_BUFFERS' is
    enabled. (CVE-2014-0198)

  - An unspecified error exists that could allow an attacker
    to cause usage of weak keying material leading to
    simplified man-in-the-middle attacks. (CVE-2014-0224)

  - An unspecified error exists related to anonymous ECDH
    cipher suites that could allow denial of service
    attacks. Note that this issue only affects OpenSSL TLS
    clients. (CVE-2014-3470)");

  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2014-0006.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to vSphere Replication 5.5.1.1 / 5.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:vmware:vsphere_replication");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/VMware vSphere Replication/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/VMware vSphere Replication/Version");
verui = get_kb_item_or_exit("Host/VMware vSphere Replication/VerUI");

if (version =~ '^5\\.[56]\\.')
{
  build = get_kb_item_or_exit("Host/VMware vSphere Replication/Build");
  if (version =~ '^5\\.5\\.' && int(build) < 1879843) fix = '5.5.1 Build 1879843';
  else if (version =~ '^5\\.6\\.') fix = '5.8.0 Build 2055179';
}

if (fix)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + verui +
      '\n  Fixed version     : ' + fix + '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'VMware vSphere Replication', verui);
