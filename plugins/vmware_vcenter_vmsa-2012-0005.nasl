#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include("compat.inc");

if (description)
{
  script_id(66812);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/02/28 11:42:29 $");

  script_cve_id("CVE-2011-3190", "CVE-2011-3375", "CVE-2012-0022");
  script_bugtraq_id(49353, 51442, 51447);
  script_osvdb_id(74818, 78331, 78573);
  script_xref(name:"VMSA", value:"2012-0005");

  script_name(english:"VMware vCenter Server Multiple Vulnerabilities (VMSA-2012-0005)");
  script_summary(english:"Checks version of VMware vCenter Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization management application installed
that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Server installed on the remote host is
4.0 before Update 4a, 4.1 before Update 3, or 5.0 before Update 1.  As
such it is potentially affected by multiple vulnerabilities in the
embedded Apache Tomcat server and the Oracle (Sun) Java Runtime
Environment.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0005.html");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2012/000198.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server 4.0 Update 4a / 4.1 Update 3 / or 5.0
Update 1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

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
if (version =~ '^VMware vCenter 4\\.0$')
{
  build = ereg_replace(pattern:'^VMware vCenter Server [0-9\\.]+ build-([0-9]+)$', string:release, replace:"\1");
  # Make sure we extracted the build number correctly
  if (build =~ '^[0-9]+$')
  {
    if (int(build) < 818020) fixversion = '4.0.0 build-818020';
  }
  else exit(1, 'Failed to extract the build number from the release string.');
}
else if (version =~ '^VMware vCenter 4\\.1$')
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
    if (int(build) < 623373) fixversion = '5.0.0 build-623373';
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
      '\n  Fixed version     : ' + fixversion + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else
{
  release = release - 'VMware vCenter Server ';
  audit(AUDIT_LISTEN_NOT_VULN, 'VMware vCenter Server', port, release);
}
