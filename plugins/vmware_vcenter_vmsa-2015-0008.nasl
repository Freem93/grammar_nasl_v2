#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87592);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/06/29 17:52:45 $");

  script_cve_id("CVE-2015-3269", "CVE-2015-5255");
  script_bugtraq_id(76394, 77626);
  script_osvdb_id(126408, 130384);
  script_xref(name:"VMSA", value:"2015-0008");

  script_name(english:"VMware vCenter Multiple Vulnerabilities (VMSA-2015-0008)");
  script_summary(english:"Checks the version of VMware vCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization management application installed
that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The VMware vCenter Server installed on the remote host is affected by
the following vulnerabilities :

  - An XML external entity (XXE) injection flaw exists in
    Flex BlazeDS in the file flex-messaging-core.jar due to
    an incorrectly configured XML parser accepting XML
    external entities from untrusted sources. A remote
    attacker can exploit this, via a specially crafted AMF
    message containing an XML external entity declaration in
    conjunction with an entity reference, to read arbitrary
    files and thus gain access to potentially sensitive
    information. (CVE-2015-3269)

  - A server-side request forgery (SSRF) vulnerability exists
    in Flex BlazeDS. A remote attacker can exploit this,
    via a crafted XML document, to direct HTTP traffic to
    intranet servers, thus bypassing access restrictions and
    allowing further host-based attacks to be conducted.
    (CVE-2015-5255)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2015-0008.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server version 5.5u3 (5.5.0 build-3000241) /
5.1u3b (5.1.0 build-3070521) / 5.0u3e (5.0.0 build-3073236) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");
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
if (version =~ '^VMware vCenter 5\\.5$' && int(build) < 3000241) fixversion = '5.5.0 build-3000241';
else if (version =~ '^VMware vCenter 5\\.1$' && int(build) < 3070521) fixversion = '5.1.0 build-3070521';
else if (version =~ '^VMware vCenter 5\\.0$' && int(build) < 3073234) fixversion = '5.0.0 build-3073236';
else audit(AUDIT_LISTEN_NOT_VULN, 'VMware vCenter', port, release);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + release +
    '\n  Fixed version     : ' + fixversion +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
