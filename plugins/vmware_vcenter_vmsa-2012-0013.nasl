#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5000) exit(0, "Nessus older than 5.x");

include("compat.inc");

if (description)
{
  script_id(66806);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/29 20:13:36 $");

  script_cve_id(
    "CVE-2011-3563",
    "CVE-2011-5035",
    "CVE-2012-0497",
    "CVE-2012-0498",
    "CVE-2012-0499",
    "CVE-2012-0500",
    "CVE-2012-0501",
    "CVE-2012-0502",
    "CVE-2012-0503",
    "CVE-2012-0504",
    "CVE-2012-0505",
    "CVE-2012-0506",
    "CVE-2012-0507",
    "CVE-2012-1711",
    "CVE-2012-1713",
    "CVE-2012-1716",
    "CVE-2012-1717",
    "CVE-2012-1718",
    "CVE-2012-1719",
    "CVE-2012-1720",
    "CVE-2012-1723",
    "CVE-2012-1725"
  );
  script_bugtraq_id(
    51194,
    52009,
    52011,
    52012,
    52013,
    52014,
    52015,
    52016,
    52017,
    52018,
    52019,
    52020,
    52161,
    53946,
    53947,
    53949,
    53950,
    53951,
    53952,
    53954,
    53956,
    53960
  );
  script_osvdb_id(
    78114,
    79225,
    79226,
    79227,
    79228,
    79229,
    79230,
    79231,
    79232,
    79233,
    79235,
    79236,
    80724,
    82874,
    82877,
    82878,
    82879,
    82880,
    82882,
    82884,
    82885,
    82886
  );
  script_xref(name:"VMSA", value:"2012-0013");
  script_xref(name:"IAVA", value:"2012-A-0147");

  script_name(english:"VMware vCenter Multiple Vulnerabilities (VMSA-2012-0013)");
  script_summary(english:"Checks version of VMware vCenter Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization management application installed
that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter installed on the remote host is 4.0
earlier than Update 4a, 4.1 earlier than Update 3, or 5.0 earlier than
Update 2.  As such, it is potentially affected by multiple
vulnerabilities in the included Oracle (Sun) Java Runtime
Environment.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0013.html");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2012/000197.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server 4.0 Update 4a / 4.1 Update 3 / 5.0
Update 2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Field Bytecode Verifier Cache Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
