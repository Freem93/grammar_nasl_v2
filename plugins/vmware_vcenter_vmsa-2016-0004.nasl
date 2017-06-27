#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90710);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/05 16:04:17 $");

  script_cve_id("CVE-2016-2076");
  script_osvdb_id(137167);
  script_xref(name:"VMSA", value:"2016-0004");

  script_name(english:"VMware vCenter Server 5.5.x < 5.5u3d / 6.0.x < 6.0u2 Client Integration Plugin Session Hijacking (VMSA-2016-0004)");
  script_summary(english:"Checks the version of VMware vCenter.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization management application installed on the remote host
is affected by a session hijacking vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Server installed on the remote host is
5.5.x prior to 5.5u3d or 6.0.x prior to 6.0u2. It is, therefore,
affected by a flaw in the VMware Client Integration Plugin due to a
failure to handle session content in a secure manner. A remote
attacker can exploit this, by convincing a user to visit a malicious
web page, to conduct a session hijacking attack. It can also be
exploited to carry out a man-in-the-middle attack.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2016-0004.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server version 5.5u3d (5.5.0 build-3721164)
/ 6.0u2 (6.0.0 build-3634788) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");
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
# only 5.5u3a, 5.5u3b and 5.5u3c are affected
# 5.5u3a is build 3142196
if (version =~ '^VMware vCenter 5\\.5$' && (int(build) < 3721164) && (int(build) >= 3142196)) fixversion = '5.5.0 build-3721164';
else if (version =~ '^VMware vCenter 6\\.0$' && int(build) < 3634788) fixversion = '6.0.0 build-3634788';
else audit(AUDIT_LISTEN_NOT_VULN, 'VMware vCenter', port, release);

report = report_items_str(
  report_items:make_array(
    "Installed version", release,
    "Fixed version", fixversion
  ),
  ordered_fields:make_list("Installed version", "Fixed version")
);
security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
