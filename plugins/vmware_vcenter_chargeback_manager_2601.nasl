#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76426);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/09 15:53:03 $");

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

  script_name(english:"VMware vCenter Chargeback Manager Multiple OpenSSL Vulnerabilities (VMSA-2014-0006)");
  script_summary(english:"Checks version of tcnative-1.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple OpenSSL vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of vCenter Chargeback Manager installed on the remote host
is 2.6.0. It is, therefore, affected by the following OpenSSL related
vulnerabilities :

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
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2014/000255.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware vCenter Chargeback Manager 2.6.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/09");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_chargeback_manager");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_vcenter_chargeback_manager_installed.nasl", "smb_enum_services.nasl");
  script_require_keys("SMB/VMware vCenter Chargeback Manager/Version");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');

app = 'VMware vCenter Chargeback Manager';
version = get_kb_item_or_exit('SMB/'+app+'/Version');
path = get_kb_item_or_exit('SMB/'+app+'/Path');

if (version !~ '^2\\.6\\.') exit(0, "The version of "+app+" installed is "+version+", not 2.6.");

if (report_paranoia < 2)
{
  status = get_kb_item_or_exit('SMB/svc/vCenterCBtomcat');
  if (status != SERVICE_ACTIVE) exit(0, 'The vCenterCBtomcat service is installed but not active.');
}

if (hotfix_is_vulnerable(dir:"\apache-tomcat\bin", file:'tcnative-1.dll', path:path, version:'1.1.30.0'))
{
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
}
