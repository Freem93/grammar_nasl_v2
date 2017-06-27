#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89115);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id(
    "CVE-2009-0034",
    "CVE-2009-0037",
    "CVE-2009-1185"
  );
  script_bugtraq_id(
    33517,
    33962,
    34536
  );
  script_osvdb_id(
    51736,
    53572,
    53810
  );
  script_xref(name:"VMSA", value:"2009-0009");
  script_xref(name:"EDB-ID", value:"8572");
  script_xref(name:"EDB-ID", value:"21848");

  script_name(english:"VMware ESX Multiple Vulnerabilities (VMSA-2009-0009) (remote check)");
  script_summary(english:"Checks the ESX version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX host is missing a security-related patch. It is,
therefore, affected by multiple vulnerabilities :

  - A flaw exists in sudo in file parse.c due to a failure
    to properly interpret a system group (%group) in the
    sudoers configuration file when handling authorization
    decisions for users belonging to that group. A local
    attacker can exploit this to gain root privileges via a
    crafted sudo command. (CVE-2009-0034)

  - A flaw exists in the redirect implementation in libcurl
    that allows arbitrary Location values to be accepted
    when CURLOPT_FOLLOWLOCATION is enabled. An attacker
    with control of a remote HTTP server can exploit this,
    via crafted redirect URLs, to trigger requests to
    intranet servers, to read or write arbitrary files, or
    to execute arbitrary commands. (CVE-2009-0037)

  - A flaw exists in udev due to a failure to verify that a
    NETLINK message originates from the kernel space. A
    local attacker can exploit this, via a crafted NETLINK
    message, to gain elevated privileges on the root file
    system. (CVE-2009-1185)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2009-0009");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESX version 4.0.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux udev Netlink Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 264, 352);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release");
  script_require_ports("Host/VMware/vsphere");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/VMware/version");
release = get_kb_item_or_exit("Host/VMware/release");
port    = get_kb_item_or_exit("Host/VMware/vsphere");

fixes = make_array();
fixes["ESX 4.0"]  = 175625;

matches = eregmatch(pattern:'^VMware (ESXi?).*build-([0-9]+)$', string:release);
if (empty_or_null(matches))
  exit(1, 'Failed to extract the ESX / ESXi build number.');

type  = matches[1];
build = int(matches[2]);

fixed_build = fixes[version];

if (!isnull(fixed_build) && build < fixed_build)
{
  padding = crap(data:" ", length:8 - strlen(type)); # Spacing alignment
 
  report = '\n  ' + type + ' version' + padding + ': ' + version +
           '\n  Installed build : ' + build +
           '\n  Fixed build     : ' + fixed_build +
           '\n';

  security_report_v4(extra:report, port:port, severity:SECURITY_HOLE);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "VMware " + version + " build " + build);
