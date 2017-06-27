#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73018);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/04/24 19:17:52 $");

  script_cve_id(
    "CVE-2014-0701",
    "CVE-2014-0703",
    "CVE-2014-0704",
    "CVE-2014-0705",
    "CVE-2014-0706",
    "CVE-2014-0707"
  );
  script_bugtraq_id(65977, 65980, 65982, 65983, 65985, 65986);
  script_osvdb_id(104024, 104025, 104026, 104027, 104028, 104029);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuf52361");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuf66202");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh33240");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh74233");
  script_xref(name:"CISCO-BUG-ID", value:"CSCue87929");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuf80681");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140305-wlc");

  script_name(english:"Multiple Vulnerabilities in Cisco Wireless LAN Controllers (cisco-sa-20140305-wlc)");
  script_summary(english:"Checks the WLC version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security update.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote Cisco Wireless LAN Controller (WLC) is affected by one or
more of the following vulnerabilities :

  - Errors exist related to the handling of specially
    crafted ethernet 802.11 frames that could allow denial
    of service attacks. (CSCue87929, CSCuf80681)

  - An error exists related to the handling of WebAuth
    logins that could allow denial of service attacks.
    (CSCuf52361)

  - An error exists related to the unintended enabling of
    the HTTP administrative interface on Aironet access
    points due to flaws in the IOS code pushed to them by
    the controller. (CSCuf66202)

  - A memory over-read error exists related to IGMP
    handling that could allow denial of service attacks.
    (CSCuh33240)

  - An error exists related to the multicast listener
    discovery (MLD) service and malformed MLD version 2
    message handling that could allow denial of service
    attacks. (CSCuh74233)"
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140305-wlc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dbc491a1");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant mitigation steps or apply the patch referenced in
Cisco Security Advisory cisco-sa-20140305-wlc. 

Note that Cisco 2000 Series WLC, Cisco 4100 Series WLC, Cisco
NM-AIR-WLC, and Cisco 500 Series Wireless Express Mobility Controllers
have reached end-of-software maintenance.  Contact the vendor for
upgrade recommendations."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

version = get_kb_item_or_exit("Host/Cisco/WLC/Version");
model = get_kb_item_or_exit("Host/Cisco/WLC/Model");

if (
  !(
    model =~ "(^|[^0-9])5\d\d($|[^0-9])" ||
    model =~ "(^|[^0-9])20\d\d($|[^0-9])" ||
    model =~ "(^|[^0-9])21\d\d($|[^0-9])" ||
    model =~ "(^|[^0-9])25\d\d($|[^0-9])" ||
    model =~ "(^|[^0-9])41\d\d($|[^0-9])" ||
    model =~ "(^|[^0-9])44\d\d($|[^0-9])" ||
    model =~ "(^|[^0-9])55\d\d($|[^0-9])" ||
    (model =~ "(^|[^0-9])75\d\d($|[^0-9])" && "catalyst" >!< tolower(model)) ||
    model =~ "(^|[^0-9])85\d\d($|[^0-9])" ||
    "AIR-WLC" >< model ||
    (model =~ "(^|[^0-9])(65\d\d|76\d\d|3750G)($|[^0-9])" && ("catalyst" >< tolower(model)))
  )
) audit(AUDIT_HOST_NOT, "affected");

fixed_version = "";

# 4.x - 7.0.x
if (version =~ "^([4-6]\.|7\.0($|[^0-9]))" && ver_compare(ver:version, fix:"7.0.250.0") < 0)
  fixed_version = "7.0.250.0 / 7.4.121.0 or later";
# 7.{1,2,3,5}.x
else if (version =~ "^7\.[1235]($|[^0-9])")
  fixed_version = "7.4.121.0 / 7.6.100.0 or later";
# 7.4.x
else if (version =~ "^7\.4\." && ver_compare(ver:version, fix:"7.4.121.0") < 0)
  fixed_version = "7.4.121.0 or later";
else
  audit(AUDIT_HOST_NOT, "affected");

if (report_verbosity > 0)
{
  report =
    '\n  Model             : ' + model +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version +
    '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
