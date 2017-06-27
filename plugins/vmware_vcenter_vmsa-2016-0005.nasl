#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91322);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/26 16:22:51 $");

  script_cve_id("CVE-2016-3427");
  script_osvdb_id(137303);
  script_xref(name:"VMSA", value:"2016-0005");

  script_name(english:"VMware vCenter Server 5.0.x < 5.0u3e / 5.1.x < 5.1u3b / 5.5.x < 5.5u3 (Linux) / 5.5.x < 5.5u3b (Windows) / 6.0.x < 6.0.0b JMX Deserialization RCE (VMSA-2016-0005)");
  script_summary(english:"Checks the version of VMware vCenter.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization management application installed on the remote host
is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Server installed on the remote host is
5.0.x prior to 5.0u3e, 5.1.x prior to 5.1u3b, 5.5.x prior to 5.5u3
(Linux), 5.5.x prior to 5.5u3b (Windows), or 6.0.x prior to 6.0.0b.
It is, therefore, affected by a flaw in Oracle JMX when deserializing
authentication credentials. An unauthenticated, remote attacker can
exploit this to execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2016-0005.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server version 5.0u3e (5.0.0 build-3073236)
/ 5.1u3b on Linux or Windows (5.1.0 build-3070521) / 5.1u3d on Windows
(5.1.0 build-3814779) / 5.5u3 on Linux (5.5.0 build-3000241) / 5.5u3b
on Windows (5.5.0 build-3252642) / 5.5u3d on Windows (5.5.0
build-3721164) / 6.0.0b (6.0.0 build-2776510) or later.

Note that vCenter Server Windows releases 5.0 u3e, 5.1 u3b, and 5.5
u3b additionally require KB 2144428 to be applied. See VMSA-2015-0007
for details. Alternatively, versions 5.1 and 5.5 on Windows may be
fixed with their respective u3d builds.

Furthermore, remote and local exploitation of this vulnerability is
feasible on vCenter Server 6.0 and 6.0.0a for Windows. Remote
exploitation is not feasible on vCenter Server 6.0.0b (and above) for
Windows but local exploitation is. The local exploitation
vulnerability can be resolved by applying the steps of KB 2145343 to
vCenter Server version 6.0.0b (and above) for Windows.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("find_service.nasl", "os_fingerprint.nasl", "vmware_vcenter_detect.nbin");
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
os = get_kb_item("Host/OS");

# Check version and build numbers
if (version =~ '^VMware vCenter 5\\.0$')
{
  # 5.0 U3e
  # Windows and Linux
  # Note that Windows requires KB 2144428
  fixbuild = 3073236;
  if (build < fixbuild)
  {
    fixversion = '5.0.0 build-'+fixbuild;
    if ("Windows" >< os) fixversion += " + KB 2144428";
  }
}
else if (version =~ '^VMware vCenter 5\\.1$')
{
  # Possible Windows fixes include:
  #   5.1 U3b with KB 2144428
  #   5.1 U3d

  fixbuild = 3070521; # 5.1 U3b for Windows and Linux
  if (build < fixbuild)
  {
    fixversion = '5.1.0 build-'+fixbuild;
    if ("Windows" >< os)
    {
      # 5.1 U3d = build 3814779
      fixversion += ' + KB 2144428 or 5.1.0 build-3814779';
    }
  }
}
else if (version =~ '^VMware vCenter 5\\.5$')
{
  # If not paranoid, let's check to see if OS is populated
  if (report_paranoia < 2 && empty_or_null(os))
    exit(0, "Can not determine version 5.5 fix build because Host/OS KB item is not set.");

  if ("Windows" >< os)
  {
    # Possible Windows fixes include:
    #   5.5 U3b with KB 2144428
    #   5.5 U3d
    fixbuild = 3252642; # 5.5 U3b
    if (build < fixbuild)
    {
      # 5.5 U3d = build 3721164
      fixversion = '5.5.0 build-'+fixbuild+' + KB 2144428 or 5.5.0 build-3721164';
    }
  }
  else
  {
    # 5.5 U3
    fixbuild = 3000241;
    if (build < fixbuild) fixversion = '5.5.0 build-'+fixbuild;
  }
}
else if (version =~ '^VMware vCenter 6\\.0$')
{
  # 6.0.0b
  # Windows and Linux
  # Note that Windows requires KB 2145343
  fixbuild = 2776510;
  if (build < fixbuild)
  {
    fixversion = '6.0.0 build-'+fixbuild;
    if ("Windows" >< os) fixversion += " + KB 2145343";
  }
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
