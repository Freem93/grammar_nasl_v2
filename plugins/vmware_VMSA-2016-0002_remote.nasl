#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88906);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id("CVE-2015-7547");
  script_bugtraq_id(83265);
  script_osvdb_id(134584);
  script_xref(name:"VMSA", value:"2016-0002");
  script_xref(name:"IAVB", value:"2016-B-0036");
  script_xref(name:"IAVB", value:"2016-B-0037");
  script_xref(name:"CERT", value:"457759");
  script_xref(name:"EDB-ID", value:"39454");

  script_name(english:"ESXi 5.5 < Build 3568722 / 6.0 < Build 3568940 glibc DNS Resolver RCE (VMSA-2016-0002) (remote check)");
  script_summary(english:"Checks the ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi host is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi host is 5.5 prior to build 3568722 or 6.0
prior to build 3568940. It is, therefore, affected by a stack-based
buffer overflow condition in the GNU C Library (glibc) DNS client-side
resolver due to improper validation of user-supplied input when
looking up names via the getaddrinfo() function. An attacker can
exploit this to execute arbitrary code by using an attacker-controlled
domain name, an attacker-controlled DNS server, or through a
man-in-the-middle attack.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2016-0002.html");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2144353");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2144357");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2144057");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2144054");
  # https://googleonlinesecurity.blogspot.com/2016/02/cve-2015-7547-glibc-getaddrinfo-stack.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8bdae0a0");
  script_set_attribute(attribute:"see_also", value:"https://sourceware.org/bugzilla/show_bug.cgi?id=18665");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

fixes = make_array(
  '5.5', '3568722',
  '6.0', '3568940'
  );

rel = get_kb_item_or_exit("Host/VMware/release");

if ("ESXi" >!< rel) audit(AUDIT_OS_NOT, "ESXi");

ver = get_kb_item_or_exit("Host/VMware/version");

# Lets extract the ESXi version
ver = ereg_replace(pattern:"^ESXi? ([0-9]+\.[0-9]+).*$", replace:"\1", string:ver);

if (
   ver !~ '^5\\.5($|[^0-9])' &&
   ver !~ '^6\\.0($|[^0-9])'
) audit(AUDIT_OS_NOT, "ESXi 5.5 / 6.0");

fixed_build = fixes[ver];

# We should never ever trigger this
if (empty_or_null(fixed_build)) audit(AUDIT_VER_FORMAT, ver);

match = eregmatch(pattern:'^VMware ESXi.*build-([0-9]+)$', string:rel);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, "VMware ESXi", "5.5 / 6.0");

build = int(match[1]);

if (build < fixed_build)
{
  report = '\n  ESXi version    : ' + ver +
           '\n  Installed build : ' + build +
           '\n  Fixed build     : ' + fixed_build +
           '\n';

  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, "VMware ESXi ", ver + " build " + build);
