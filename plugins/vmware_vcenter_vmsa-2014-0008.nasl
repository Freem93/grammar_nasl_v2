#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77728);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/29 20:13:36 $");

  script_cve_id(
    "CVE-2013-4322",
    "CVE-2013-4590",
    "CVE-2013-6629",
    "CVE-2013-6954",
    "CVE-2014-0050",
    "CVE-2014-0114",
    "CVE-2014-0429",
    "CVE-2014-0432",
    "CVE-2014-0446",
    "CVE-2014-0449",
    "CVE-2014-0451",
    "CVE-2014-0452",
    "CVE-2014-0453",
    "CVE-2014-0454",
    "CVE-2014-0455",
    "CVE-2014-0456",
    "CVE-2014-0457",
    "CVE-2014-0458",
    "CVE-2014-0459",
    "CVE-2014-0460",
    "CVE-2014-0461",
    "CVE-2014-1876",
    "CVE-2014-2397",
    "CVE-2014-2401",
    "CVE-2014-2402",
    "CVE-2014-2403",
    "CVE-2014-2409",
    "CVE-2014-2412",
    "CVE-2014-2413",
    "CVE-2014-2414",
    "CVE-2014-2420",
    "CVE-2014-2421",
    "CVE-2014-2423",
    "CVE-2014-2427",
    "CVE-2014-2428"
  );
  script_bugtraq_id(
    63676,
    64493,
    65400,
    65568,
    65767,
    65768,
    66856,
    66866,
    66870,
    66873,
    66877,
    66879,
    66881,
    66883,
    66887,
    66891,
    66893,
    66894,
    66897,
    66898,
    66899,
    66902,
    66903,
    66905,
    66907,
    66909,
    66910,
    66911,
    66914,
    66915,
    66916,
    66917,
    66918,
    66919,
    67121
  );
  script_osvdb_id(
    99711,
    101309,
    102808,
    102945,
    103706,
    103707,
    105866,
    105867,
    105868,
    105869,
    105871,
    105872,
    105873,
    105874,
    105875,
    105877,
    105878,
    105879,
    105880,
    105881,
    105882,
    105883,
    105884,
    105885,
    105886,
    105887,
    105889,
    105890,
    105891,
    105892,
    105895,
    105896,
    105897,
    105898,
    106409
  );
  script_xref(name:"VMSA", value:"2014-0008");

  script_name(english:"VMware Security Updates for vCenter Server (VMSA-2014-0008)");
  script_summary(english:"Checks the version of VMware vCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization management application installed
that is affected by multiple security vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The VMware vCenter Server installed on the remote host is version 5.0
prior to Update 3c, 5.1 prior to Update 3, or 5.5 prior to Update 2.
It is, therefore, affected by multiple vulnerabilities in third party
libraries :

  - The bundled version of Apache Struts contains a code
    execution flaw. Note that 5.0 Update 3c only addresses
    this vulnerability. (CVE-2014-0114)

  - The bundled tc-server / Apache Tomcat contains multiple
    vulnerabilities. (CVE-2013-4590, CVE-2013-4322, and
    CVE-2014-0050)

  - The bundled version of Oracle JRE is prior to 1.7.0_55
    and thus is affected by multiple vulnerabilities. Note
    that this only affects version 5.5 of vCenter.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2014-0008.html");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2014/000280.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server 5.5u2 (5.5.0 build-2001466) / 5.1u3
(5.1.0 build-2306353) / 5.0u3c (5.0.0 build-2210222) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts ClassLoader Manipulation Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

# Check version and build numbers
if (version =~ '^VMware vCenter 5\\.0$' && int(build) < 2210222) fixversion = '5.0.0 build-2210222';
else if (version =~ '^VMware vCenter 5\\.1$' && int(build) < 2306353) fixversion = '5.1.0 build-2306353';
else if (version =~ '^VMware vCenter 5\\.5$' && int(build) < 2001466) fixversion = '5.5.0 build-2001466';
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
