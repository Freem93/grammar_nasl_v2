#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86255);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id("CVE-2015-1047", "CVE-2015-2342");
  script_osvdb_id(128332, 128333);
  script_xref(name:"VMSA", value:"2015-0007");
  script_xref(name:"IAVA", value:"2015-A-0236");
  script_xref(name:"IAVA", value:"2015-A-0237");
  script_xref(name:"EDB-ID", value:"36101");
  script_xref(name:"ZDI", value:"ZDI-15-455");

  script_name(english:"VMware vCenter Multiple Vulnerabilities (VMSA-2015-0007)");
  script_summary(english:"Checks the version of VMware vCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization management application installed
that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The VMware vCenter Server installed on the remote host is affected by
the following vulnerabilities :

  - A flaw exists in the vpxd service due to improper
    sanitization of long heartbeat messages. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service. (CVE-2015-1047)

  - A flaw exists due to an insecurely configured and
    remotely accessible JMX RMI service. An unauthenticated,
    remote attacker can exploit this, via an MLet file, to
    execute arbitrary code on the vCenter server with the
    same privileges as the web server. (CVE-2015-2342)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2015-0007.html");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-455/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server 6.0.0b (6.0.0 build-2776510), 5.5u3
(5.5.0 build-3000241), 5.1u3b (5.1.0 build-3070521), or 5.0u3e (5.0.0
build-3073234) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java JMX Server Insecure Configuration Java Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_vcenter_detect.nbin");
  script_require_keys("Host/VMware/vCenter", "Host/VMware/version", "Host/VMware/release");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_kb_item_or_exit("Host/VMware/vCenter");
version = get_kb_item_or_exit("Host/VMware/version");
release = get_kb_item_or_exit("Host/VMware/release");

# Extract and verify the build number
build = ereg_replace(pattern:'^VMware vCenter Server [0-9\\.]+ build-([0-9]+)$', string:release, replace:"\1");
if (build !~ '^[0-9]+$') exit(1, 'Failed to extract the build number from the release string.');

release = release - 'VMware vCenter Server ';
fixversion = NULL;

# Check version and build numbers
if (version =~ '^VMware vCenter 6\\.0$' && int(build) < 2776510) fixversion = '6.0.0 build-2776510';
else if (version =~ '^VMware vCenter 5\\.5$' && int(build) < 3000241) fixversion = '5.5.0 build-3000241';
else if (version =~ '^VMware vCenter 5\\.1$' && int(build) < 3070521) fixversion = '5.1.0 build-3070521';
else if (version =~ '^VMware vCenter 5\\.0$' && int(build) < 3073234) fixversion = '5.0.0 build-3073234';
else audit(AUDIT_LISTEN_NOT_VULN, 'VMware vCenter', port, release);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + release +
    '\n  Fixed version     : ' + fixversion +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
