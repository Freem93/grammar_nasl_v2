#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(69985);
 script_version("$Revision: 1.7 $");
 script_cvs_date("$Date: 2016/05/04 18:02:13 $");

 script_cve_id("CVE-2007-5134");
 script_bugtraq_id(25822);
 script_osvdb_id(37504);
 script_xref(name:"CISCO-BUG-ID", value:"CSCek49649");
 script_xref(name:"CISCO-SR", value:"cisco-sr-20070926-lb");

 script_name(english:"Cisco Catalyst 6500 and Cisco 7600 Series Devices Accessible via Loopback Address (cisco-sr-20070926-lb)");
 script_summary(english:"Checks the version of Cisco IOS");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
"The remote Cisco Catalyst 6500 and Cisco 7600 series device is affected
by an issue that could allow remote attackers to send packets to an
interface for which network exposure was unintended. 

It should be noted that while the vendor describes a possible
workaround, this plugin does not test for the presence of that
workaround.");
 # http://tools.cisco.com/security/center/content/CiscoSecurityResponse/cisco-sr-20070926-lb
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?15da12b5");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant update referenced in Cisco Security Advisory
cisco-sr-20070926-lb.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/27");
 script_set_attribute(attribute:"patch_publication_date", value:"2009/09/27");
 script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/19");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:catalyst");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2013-2016 Tenable Network Security, Inc.");
 script_family(english:"CISCO");

 script_dependencies("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");
 exit(0);
}

include("audit.inc");
include("cisco_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# check model
model = get_kb_item("CISCO/model");
if (model)
{
  if (
    (model != "cat6500FirewallSm") &&
    (model != "catalyst65xxVirtualSwitch") &&
    (model != "catalyst6kSup720") &&
    (model != "ciscoNMAONWS") &&
    (model != "ciscoWSC6509neba") &&
    (model != "ciscoWSC6509ve") &&
    (model != "ciscoWsSvcFwm1sc") &&
    (model != "ciscoWsSvcFwm1sy") &&
    (model !~ "cisco76\d+")
  ) audit(AUDIT_HOST_NOT, "affected");
}
else
{
  model = get_kb_item_or_exit("Host/Cisco/IOS/Model");
  if (model !~ "65[0-9][0-9]" && model !~ "76[0-9][0-9]") audit(AUDIT_HOST_NOT, "affected");
}

# check os version
if (check_release(version: version, patched:make_list("12.2(33)SXH") )) flag = 1;

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  HW model          : ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 12.2(33)SXH or later\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else audit(AUDIT_HOST_NOT, "affected");
