#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90708);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/09/12 13:45:33 $");

  script_cve_id("CVE-2016-1268");
  script_osvdb_id(137063);
  script_xref(name:"JSA", value:"JSA10732");

  script_name(english:"Juniper ScreenOS 6.3.x < 6.3.0r21 Malformed SSL/TLS Packet DoS (JSA10732)");
  script_summary(english:"Checks the version of ScreenOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Juniper ScreenOS that is 6.3.x
prior to 6.3.0r21. It is, therefore, affected by a denial of service
vulnerability in the administrative web services that is triggered
when handling malformed SSL/TLS packets. An unauthenticated, remote
attacker can exploit this, via a crafted SSL packet, to cause the loss
of administrative access or to reboot the system.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://kb.juniper.net/InfoCenter/index?page=content&id=JSA10732");
  # http://www.juniper.net/techpubs/en_US/screenos6.3.0/information-products/pathway-pages/screenos/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4eb1929");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Juniper ScreenOS version 6.3.0r21 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/04/13");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/26");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:juniper:screenos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("screenos_version.nbin");
  script_require_keys("Host/Juniper/ScreenOS/display_version", "Host/Juniper/ScreenOS/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Juniper ScreenOS";
display_version = get_kb_item_or_exit("Host/Juniper/ScreenOS/display_version");
version = get_kb_item_or_exit("Host/Juniper/ScreenOS/version");
respin_version = get_kb_item("Host/Juniper/ScreenOS/respin_version");

display_fix = NULL;

# 6.3.0r19b and prior are affected. 6.2 unsupported.
# fix is 6.3.0r21 and later
if (version =~ "^6\.3([^0-9]|$)" && ver_compare(ver:version, fix:"6.3.0.19", strict:FALSE) <= 0)
{
  display_fix = "6.3.0r21";
  if (
    version == "6.3.0.19" &&
    !empty_or_null(respin_version) &&
    respin_version !~ "^[ab]$"
  ) display_fix = NULL;
}

if(display_fix)
{
  port = 0;
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + display_version +
      '\n  Fixed version     : ' + display_fix +
      '\n';

    security_hole(extra:report, port:port);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);
