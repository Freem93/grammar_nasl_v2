#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include("compat.inc");

if (description)
{
  script_id(65223);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/11/09 03:38:39 $");

  script_cve_id("CVE-2013-1659");
  script_bugtraq_id(58115);
  script_osvdb_id(90554);
  script_xref(name:"VMSA", value:"2013-0003");

  script_name(english:"VMware vCenter Server NFC Protocol Code Execution (VMSA-2013-0003)");
  script_summary(english:"Checks version of VMware vCenter");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization management application installed
that is affected by a code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter installed on the remote host is 4.0
before update 4b, 5.0 before update 2, or 5.1 before 5.1.0b.  Such
versions are potentially affected by a denial of service vulnerability
due to an issue in webservice logging.  By exploiting this flaw, a
remote, unauthenticated attacker could crash the affected host.");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2013/000205.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter 4.0 update 4b, 5.0 before update 2, or 5.1
before 5.1.0b");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("vmware_vcenter_detect.nbin");
  script_require_keys("Host/VMware/vCenter", "Host/VMware/version", "Host/VMware/release");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

port = get_kb_item_or_exit("Host/VMware/vCenter");
version = get_kb_item_or_exit("Host/VMware/version");
release = get_kb_item_or_exit("Host/VMware/release");

if (version =~ '^VMware vCenter 4\\.0$')
{
  build = ereg_replace(pattern:'^VMware vCenter Server [0-9\\.]+ build-([0-9]+)$', string:release, replace:"\1");
  # Make sure we extracted the build number correctly
  if (build =~ '^[0-9]+$')
  {
    if (int(build) < 934016) fixversion = '4.0.0 build-934016';
  }
  else exit(1, 'Failed to extract the build number from the release string.');
}
else if (version =~ '^VMware vCenter 5\\.0$')
{
  build = ereg_replace(pattern:'^VMware vCenter Server [0-9\\.]+ build-([0-9]+)$', string:release, replace:"\1");
  # Make sure we extracted the build number correctly
  if (build =~ '^[0-9]+$')
  {
    if (int(build) < 913577) fixversion = '5.0.0 build-913577';
  }
  else exit(1, 'Failed to extract the build number from the release string.');
}
else if (version =~ '^VMware vCenter 5\\.1$')
{
  build = ereg_replace(pattern:'^VMware vCenter Server [0-9\\.]+ build-([0-9]+)$', string:release, replace:"\1");
  # Make sure we extracted the build number correctly
  if (build =~ '^[0-9]+$')
  {
    if (int(build) < 947673) fixversion = '5.1.0 build-947673';
  }
  else exit(1, 'Failed to extract the build number from the release string.');
}

if (fixversion)
{
  if (report_verbosity > 0)
  {
    release = release - 'VMware vCenter Server ';
    report =
      '\n  Installed version : ' + release +
      '\n  Fixed version : ' + fixversion + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else
{
  release = release - 'VMware vCenter Server ';
  audit(AUDIT_LISTEN_NOT_VULN, 'VMware vCenter', port, release);
}
