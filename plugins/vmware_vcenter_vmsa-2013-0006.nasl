#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include("compat.inc");

if (description)
{
  script_id(66274);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/19 18:10:50 $");

  script_cve_id("CVE-2012-2733", "CVE-2012-4534", "CVE-2013-3107");
  script_bugtraq_id(56402, 56813, 59508);
  script_osvdb_id(87227, 88095, 92812);
  script_xref(name:"VMSA", value:"2013-0006");

  script_name(english:"VMware Security Updates for vCenter Server (VMSA-2013-0006)");
  script_summary(english:"Checks version of VMware vCenter");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization management application installed
that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter installed on the remote host is 5.1 prior
to update 1.  It therefore is potentially affected by the following
vulnerabilities :

  - When deployed in an environment that uses Active
    Directory with anonymous LDAP binding enabled, VMware
    vCenter doesn't properly handle login credentials.
    (CVE-2013-3107)

  - The bundled version of Oracle JRE is earlier than
    1.6.0_37 and thus, is affected by multiple security
    issues.

  - The bundled version of Apache Tomcat is affected by
    multiple issues. (CVE-2012-2733, CVE-2012-4534)");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2013-0006.html");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2013/000209.html");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b0eb44d4");
  # http://www.oracle.com/technetwork/topics/security/javacpuoct2012-1515924.html
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware vCenter 5.1 update 1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/02"); # CVE-2012-2733
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

if (version =~ '^VMware vCenter 5\\.0$')
{
  build = ereg_replace(pattern:'^VMware vCenter Server [0-9\\.]+ build-([0-9]+)$', string:release, replace:"\1");
  # Make sure we extracted the build number correctly
  if (build =~ '^[0-9]+$')
  {
    if (int(build) < 1300600) fixversion = '5.0.0 build-1300600';
  }
  else exit(1, 'Failed to extract the build number from the release string.');
}
else if (version =~ '^VMware vCenter 5\\.1$')
{
  build = ereg_replace(pattern:'^VMware vCenter Server [0-9\\.]+ build-([0-9]+)$', string:release, replace:"\1");
  # Make sure we extracted the build number correctly
  if (build =~ '^[0-9]+$')
  {
    if (int(build) < 1064983) fixversion = '5.1.0 build-1064983';
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
  audit(AUDIT_LISTEN_NOT_VULN, 'VMware vCenter', port, release);
}
