#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91713);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/06/21 16:59:01 $");

  script_cve_id("CVE-2015-6931");
  script_osvdb_id(140126);
  script_xref(name:"VMSA", value:"2016-0009");

  script_name(english:"VMware vCenter Server 5.0.x < 5.0u3g / 5.1.x < 5.1u3d / 5.5.x < 5.5u2d Reflected XSS (VMSA-2016-0009)");
  script_summary(english:"Checks the version of VMware vCenter.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization management application installed on the remote host
is affected by a reflected cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Server installed on the remote host is
5.0.x prior to 5.0u3g, 5.1.x prior to 5.1u3d, or 5.5.x prior to
5.5u2d. It is, therefore, affected by a reflected cross-site scripting
(XSS) vulnerability due to improper sanitization of input. An
unauthenticated, remote attacker can exploit this issue, by convincing
a user into clicking a malicious link, to execute arbitrary scripting
code in the user's browser session.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2016-0009.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server version 5.0u3g (5.0.0 build-3891026)
/ 5.1u3d (5.1.0 build-3814779) / 5.5u2d (5.5.0 build-2442329) or
later.

Note that the client side component of the vSphere Web Client does not
need to be updated to remediate CVE-2015-6931. Updating the vCenter
Server is sufficient to remediate this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

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
if (empty_or_null(build) || build !~ '^[0-9]+$') audit(AUDIT_UNKNOWN_BUILD, "VMware vCenter Server");

build = int(build);
release = release - 'VMware vCenter Server ';
fixversion = NULL;

# Check version and build numbers
if (version =~ '^VMware vCenter 5\\.0$')
{
  # 5.0 U3g
  fixbuild = 3891026;
  if (build < fixbuild)
    fixversion = '5.0.0 build-'+fixbuild+' (Update 3g)';
}
else if (version =~ '^VMware vCenter 5\\.1$')
{
  # 5.1 U3d
  fixbuild = 3814779;
  if (build < fixbuild)
    fixversion = '5.1.0 build-'+fixbuild+' (Update 3d)';
}
else if (version =~ '^VMware vCenter 5\\.5$')
{
  # 5.5 U2d
  fixbuild = 2442329;
  if (build < fixbuild)
    fixversion = '5.5.0 build-'+fixbuild+' (Update 2d)';
}

if (isnull(fixversion))
  audit(AUDIT_LISTEN_NOT_VULN, 'VMware vCenter', port, release);

report = report_items_str(
  report_items:make_array(
    "Installed version", release,
    "Fixed version", fixversion
  ),
  ordered_fields:make_list("Installed version", "Fixed version")
);
security_report_v4(port:port, severity:SECURITY_WARNING, extra:report, xss:TRUE);
