#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79865);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/18 04:40:38 $");

  script_cve_id(
    "CVE-2014-0015",
    "CVE-2014-0138",
    "CVE-2014-0191",
    "CVE-2014-2483",
    "CVE-2014-2490",
    "CVE-2014-4208",
    "CVE-2014-4209",
    "CVE-2014-4216",
    "CVE-2014-4218",
    "CVE-2014-4219",
    "CVE-2014-4220",
    "CVE-2014-4221",
    "CVE-2014-4223",
    "CVE-2014-4227",
    "CVE-2014-4244",
    "CVE-2014-4247",
    "CVE-2014-4252",
    "CVE-2014-4262",
    "CVE-2014-4263",
    "CVE-2014-4264",
    "CVE-2014-4265",
    "CVE-2014-4266",
    "CVE-2014-4268",
    "CVE-2014-8371"
  );
  script_bugtraq_id(
    65270,
    66457,
    67233,
    68562,
    68571,
    68576,
    68580,
    68583,
    68590,
    68596,
    68599,
    68603,
    68608,
    68612,
    68615,
    68620,
    68624,
    68626,
    68632,
    68636,
    68639,
    68642,
    68645,
    71493
  );
  script_osvdb_id(
    102715,
    104972,
    106710,
    109124,
    109125,
    109126,
    109127,
    109128,
    109129,
    109130,
    109131,
    109132,
    109133,
    109134,
    109135,
    109136,
    109137,
    109138,
    109139,
    109140,
    109141,
    109142,
    109143,
    115364
  );
  script_xref(name:"VMSA", value:"2014-0012");

  script_name(english:"VMware Security Updates for vCenter Server (VMSA-2014-0012)");
  script_summary(english:"Checks the version of VMware vCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization management application installed
that is affected by multiple security vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The VMware vCenter Server installed on the remote host is version 5.0
prior to Update 3c, 5.1 prior to Update 3, or 5.5 prior to Update 2.
It is, therefore, affected by multiple vulnerabilities in third party
libraries :

  - Due to improper certificate validation when connecting
    to a CIM server on an ESXi host, an attacker can
    perform man-in-the-middle attacks. (CVE-2014-8371)

  - The bundled version of Oracle JRE is prior to 1.6.0_81
    and thus is affected by multiple vulnerabilities. Note
    that this only affects version 5.1 and 5.0 of vCenter
    but is only fixed in 5.1 Update 3.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2014-0012.html");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2014/000283.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server 5.5u2 (5.5.0 build-2001466) / 5.1u3
(5.1.0 build-2306353) / 5.0u3c (5.0.0 build-2210222) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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
