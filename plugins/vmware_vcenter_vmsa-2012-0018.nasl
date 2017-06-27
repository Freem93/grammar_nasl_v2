#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include("compat.inc");

if (description)
{
  script_id(65209);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/29 00:33:21 $");

  script_cve_id("CVE-2012-6326");
  script_bugtraq_id(58139);
  script_osvdb_id(90580);
  script_xref(name:"VMSA", value:"2012-0018");

  script_name(english:"VMware vCenter Server Denial of Service (VMSA-2012-0018)");
  script_summary(english:"Checks version of VMware vCenter");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization management application installed
that is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter installed on the remote host is 4.1
before update 3 or 5.0 before Update 2.  Such versions are potentially
affected by a denial of service vulnerability due to an issue in
webservice logging.  By exploiting this flaw, a remote, unauthenticated
attacker could crash the affected host.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0018.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware vCenter 4.1 Update 3 or 5.0 Update 2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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

fixversion = "";
if (version =~ '^VMware vCenter 4\\.1$')
{
  build = ereg_replace(pattern:'^VMware vCenter Server [0-9\\.]+ build-([0-9]+)$', string:release, replace:"\1");
  # Make sure we extracted the build number correctly
  if (build =~ '^[0-9]+$')
  {
    if (int(build) < 799345) fixversion = '4.1.0 build-799345';
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
