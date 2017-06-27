#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95468);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/20 19:56:06 $");

  script_cve_id("CVE-2016-7459", "CVE-2016-7460");
  script_bugtraq_id(94485, 94486);
  script_osvdb_id(
    147774,
    147775,
    147776,
    147777
  );
  script_xref(name:"VMSA", value:"2016-0022");
  script_xref(name:"IAVB", value:"2016-B-0173");
  script_xref(name:"IAVB", value:"2016-B-0174");

  script_name(english:"VMware vCenter Server 5.5.x < 5.5u3e / 6.0.x < 6.0u2a Multiple XXE Vulnerabilities (VMSA-2016-0022)");
  script_summary(english:"Checks the version of VMware vCenter.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization management application installed on the remote host
is affected by multiple XML external entity (XXE) vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Server installed on the remote host is
5.5.x prior to 5.5u3e or 6.0.x prior to 6.0u2a. It is, therefore,
affected by multiple XML external entity (XXE) vulnerabilities :

  - Multiple XML external entity (XXE) vulnerabilities exist
    in the Log Browser, the Distributed Switch setup, and
    the Content Library due to an incorrectly configured XML
    parser accepting XML external entities from an untrusted
    source. An unauthenticated, remote attacker can exploit
    this, via specially crafted XML data, to disclose the
    contents of arbitrary files. (CVE-2016-7459)

  - An XML external entity (XXE) vulnerability exists in the
    Single Sign-On functionality due to an incorrectly 
    configured XML parser accepting XML external entities
    from an untrusted source. An unauthenticated, remote
    attacker can exploit this, via specially crafted XML
    data, to disclose the contents of arbitrary files or
    cause a denial of service condition. (CVE-2016-7460)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2016-0022.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server version 5.5.u3e (5.5.0 build-4180646)
/ 6.0u2a (6.0.0 build-4541947) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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
if (version =~ '^VMware vCenter 5\\.5$' && int(build) < 4180646) fixversion = '5.5.0 build-4180646';
else if (version =~ '^VMware vCenter 6\\.0$' && int(build) < 4541947) fixversion = '6.0.0 build-4541947';
else audit(AUDIT_LISTEN_NOT_VULN, 'VMware vCenter', port, release);

report = report_items_str(
  report_items:make_array(
    "Installed version", release,
    "Fixed version", fixversion
  ),
  ordered_fields:make_list("Installed version", "Fixed version")
);
security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
