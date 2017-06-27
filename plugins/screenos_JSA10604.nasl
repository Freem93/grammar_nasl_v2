#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74367);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/06 18:38:46 $");

  script_cve_id("CVE-2013-6958");
  script_bugtraq_id(64260);
  script_osvdb_id(100861);

  script_name(english:"Juniper ScreenOS 5.4 < 5.4.0r28 / 6.2 < 6.2.0r18 / 6.3 < 6.3.0r16 Malformed ICMP Echo Request DoS (JSA10604)");
  script_summary(english:"Checks version of ScreenOS.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Juniper ScreenOS prior to
5.4.0r28 / 6.2.0r18 / 6.3.0r16. It is, therefore, affected by a denial
of service vulnerability due to a failure to properly handle ICMP echo
request packets.

A remote, unauthenticated attacker could potentially exploit this
vulnerability by sending malformed ICMP echo request packets to cause
a firewall crash or failover. Repeated exploitation can result in an
extended denial of service condition.

Note that the host is not affected if the 'Ping of Death' screen is
enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10604");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2014/Jan/73");
  script_set_attribute(attribute:"solution", value:
"Upgrade to 5.4.0r28 / 6.2.0r18 / 6.3.0r16 or later or apply the
workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:screenos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("screenos_version.nbin");
  script_require_keys("Host/Juniper/ScreenOS/display_version", "Host/Juniper/ScreenOS/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# This is a paranoid check because the Ping of Death screen may be enabled
if (report_paranoia < 2) audit(AUDIT_PARANOID);

kb_base  = "Host/Juniper/ScreenOS/";
display_version = get_kb_item_or_exit(kb_base + "display_version");
version = get_kb_item_or_exit(kb_base + "version");

if (version =~ "^5\.4\.")
  model   = get_kb_item_or_exit(kb_base + "model");

app_name = "Juniper ScreenOS";
display_fix = NULL;

if (version =~ "^5\.4([^0-9]|$)" && "5GT" >< model && ver_compare(ver:version, fix:"5.4.0.28", strict:FALSE) == -1)
  display_fix = "5.4.0r28";
else if (version =~ "^6\.2([^0-9]|$)" && ver_compare(ver:version, fix:"6.2.0.18", strict:FALSE) == -1)
  display_fix = "6.2.0r18";
else if (version =~ "^6\.3([^0-9]|$)" && ver_compare(ver:version, fix:"6.3.0.16", strict:FALSE) == -1)
  display_fix = "6.3.0r16";

if (!isnull(display_fix))
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
