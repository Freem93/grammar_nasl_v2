#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99475);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/04/19 16:18:45 $");

  script_cve_id("CVE-2017-5641");
  script_bugtraq_id(97383);
  script_osvdb_id(155134);
  script_xref(name:"VMSA", value:"2017-0007");
  script_xref(name:"CERT", value:"307983");

  script_name(english:"VMware vCenter Server 6.0.x < 6.0u3b / 6.5.x < 6.5c BlazeDS AMF3 RCE (VMSA-2017-0007)");
  script_summary(english:"Checks the version of VMware vCenter.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization management application installed on the remote host
is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Server installed on the remote host is
6.0.x prior to 6.0u3b or 6.5.x prior to 6.5c. It is, therefore,
affected by a flaw in FlexBlazeDS when processing AMF3 messages due to
allowing the instantiation of arbitrary classes when deserializing
objects. An unauthenticated, remote attacker can exploit this, by
sending a specially crafted Java object, to execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2017-0007.html");
  # http://pubs.vmware.com/Release_Notes/en/vsphere/60/vsphere-vcenter-server-60u3b-release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e032520");
  # http://pubs.vmware.com/Release_Notes/en/vsphere/65/vsphere-vcenter-server-650c-release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a1fa223");
  script_set_attribute(attribute:"see_also", value:"http://codewhitesec.blogspot.de/2017/04/amf.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server version 6.0u3b (6.0.0 build-5326177)
/ 6.0u3b on Windows (6.0.0 build-5318198) / 6.5.0c (6.5.0
build-5318112) or later. Alternatively, apply the vendor-supplied
workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("find_service.nasl", "os_fingerprint.nasl", "vmware_vcenter_detect.nbin");
  script_require_keys("Host/VMware/vCenter", "Host/VMware/version", "Host/VMware/release");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port    = get_kb_item_or_exit("Host/VMware/vCenter");
version = get_kb_item_or_exit("Host/VMware/version");
release = get_kb_item_or_exit("Host/VMware/release");

# Extract and verify the build number
build = ereg_replace(
  pattern:'^VMware vCenter Server [0-9\\.]+ build-([0-9]+)$',
  string:release, replace:"\1"
);

if (empty_or_null(build) || build !~ '^[0-9]+$')
  audit(AUDIT_UNKNOWN_BUILD, "VMware vCenter Server");

build      = int(build);
release    = release - 'VMware vCenter Server ';
fixversion = NULL;
os         = get_kb_item("Host/OS");

# Check version and build numbers
if (version =~ "^VMware vCenter 6\.0($|[^0-9])")
{
  # If not paranoid, let's check to see if OS is populated
  if (report_paranoia < 2 && empty_or_null(os))
    exit(0, "Can not determine version 6.0 fix build because Host/OS KB item is not set.");

  # vCenter Server 6.0 Update 3b on Windows | 13 APR 2017 | ISO Build 5318198
  # Windows
  if ("windows" >< tolower(os))
  {
    fixbuild = 5318198;
    if (build < fixbuild) fixversion = '6.0.0 build-'+fixbuild;
  }

  # vCenter Server 6.0 Update 3b | 13 APR 2017 | ISO Build 5326177
  # Standard
  else
  {
    fixbuild = 5326177;
    if (build < fixbuild) fixversion = '6.0.0 build-'+fixbuild;
  }
}
else if (version =~ "^VMware vCenter 6\.5($|[^0-9])")
{
  # vCenter Server 6.5.0c | 13 APRIL 2017 | ISO Build 5318112
  # Standard
  fixbuild = 5318112;
  if (build < fixbuild) fixversion = '6.5.0 build-'+fixbuild;
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
security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
