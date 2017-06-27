#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77760);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/09/24 20:59:29 $");

  script_cve_id("CVE-2014-3362");
  script_bugtraq_id(69737);
  script_osvdb_id(111302);

  script_name(english:"Unsupported Cisco MXP Series Device");
  script_summary(english:"Detects unsupported MXP devices.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is no longer supported by the vendor.");
  script_set_attribute(attribute:"description", value:
"The remote host is a Cisco MXP series device. Cisco has discontinued
support for all MXP series devices.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # http://www.cisco.com/c/en/us/products/collaboration-endpoints/eos-eol-listing.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9742f6fb");
  script_set_attribute(attribute:"solution", value:"Switch to a supported product.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_system_software");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_mcu_detect.nasl", "telnetserver_detect_type_nd_version.nasl");

  script_require_ports("SNMP/sysDesc", "Services/ftp", 21, "Services/telnet", 23);
  exit(0);
}

include("audit.inc");
include("telnet_func.inc");
include("global_settings.inc");
include("misc_func.inc");

app = 'Cisco MXP';
vuln = FALSE;

version = get_kb_item("Cisco/TelePresence_MCU/Version");
device = get_kb_item("Cisco/TelePresence_MCU/Device");

if(!isnull(device)) device = tolower(device);

if(!isnull(version) &&
   !isnull(device) && device =~ "[0-9]mxp(\s|$)" &&
   ("tandberg" >< device || "telepresence" >< device))
{
  # sanity check version (should be <= 9.x)
  if(version !~ "^F\d\.")
    audit(AUDIT_INST_VER_NOT_VULN, 'Cisco ' + device, version);
  vuln = TRUE;
}

if(!vuln)
{
  port = get_service(svc:"telnet", default:23, exit_on_fail:TRUE);

  banner = get_telnet_banner(port:port);
  if (!banner) audit(AUDIT_NO_BANNER, port);

  # checks for MXP version string, since 'MXP' is usually not in the
  # telnet banner
  ver_item = eregmatch(pattern:"Release (F[\d.]+) (NTSC|PAL)", string:banner);

  if(isnull(ver_item) || isnull(ver_item[1]) || "tandberg codec" >!< tolower(banner))
    audit(AUDIT_HOST_NOT, app);

  # sanity check version (should be <= 9.x)
  item = eregmatch(pattern:"Release (F\d\.[\d.]+) (NTSC|PAL)", string:banner);
  if(isnull(item) || isnull(item[1]))
    exit(0, "The remote host is either *not* running a recognized MXP software version or is not an MXP series device.");

  version = item[1];
}

register_unsupported_product(product_name:"Cisco TelePresence",
                             version:version, cpe_base:"cisco:telepresence_system_software");

if(report_verbosity > 0)
{
  report = '\n  Version : ' + version + '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
