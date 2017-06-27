#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78826);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2017/04/25 20:29:05 $");

  script_cve_id(
    "CVE-2014-6271",
    "CVE-2014-7169",
    "CVE-2014-7186",
    "CVE-2014-7187",
    "CVE-2014-6277",
    "CVE-2014-6278"
  );
  script_bugtraq_id(
    70103,
    70137,
    70152,
    70154,
    70165,
    70166
  );
  script_osvdb_id(
    112004,
    112096,
    112097,
    112158,
    112169
  );
  script_xref(name:"VMSA", value:"2014-0010");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");
  script_xref(name:"EDB-ID", value:"34860");

  script_name(english:"VMware NSX Bash Environment Variable Command Injection (VMSA-2014-0010) (Shellshock)");
  script_summary(english:"Checks the version of VMware NSX.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware NSX installed on the remote host is 4.x prior to
4.0.5 / 4.1.4 / 4.2.1 or 6.x prior to 6.0.7 / 6.1.1. It is, therefore,
affected by a command injection vulnerability in GNU Bash known as
Shellshock, which is due to the processing of trailing strings after
function definitions in the values of environment variables. This
allows a remote attacker to execute arbitrary code via environment
variable manipulation depending on the configuration of the system.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2014-0010");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/650");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/blogs/766093/posts/1976383");
  script_set_attribute(attribute:"see_also", value:"https://www.invisiblethreat.ca/post/shellshock/");
  # http://lcamtuf.blogspot.com/2014/10/bash-bug-how-we-finally-cracked.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e40f2f5a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware NSX version 4.0.5 / 4.1.4 / 4.2.1 / 6.0.7 / 6.1.1 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CUPS Filter Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:nsx");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("vmware_nsx_installed.nbin");
  script_require_keys("Host/VMware NSX/Product", "Host/VMware NSX/Version", "Host/VMware NSX/Build");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

product = get_kb_item_or_exit("Host/VMware NSX/Product");
version = get_kb_item_or_exit("Host/VMware NSX/Version");
build   = get_kb_item_or_exit("Host/VMware NSX/Build");
product_name = "VMware NSX " + product;

fix = '';

if (version =~ '^4\\.0\\.' && int(build) < '39236') fix = '4.0.5 Build 39236';
else if (version =~ '^4\\.1\\.' && int(build) < '39250') fix = '4.1.4 Build 39250';
else if (version =~ '^4\\.2\\.' && int(build) < '39256') fix = '4.2.1 Build 39256';
else if (version =~ '^6\\.0\\.' && int(build) < '2176282') fix = '6.0.7 Build 2176282';
else if (version =~ '^6\\.1\\.' && int(build) < '2179522') fix = '6.1.1 Build 2179522';
else audit(AUDIT_INST_VER_NOT_VULN, product_name, version, build);

report =
  '\n  Installed product : ' + product_name +
  '\n  Installed version : ' + version + ' Build ' + build +
  '\n  Fixed version     : ' + fix + 
  '\n';
security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
