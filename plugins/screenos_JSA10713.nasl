#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87507);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/04/29 19:33:19 $");

  script_cve_id("CVE-2015-7755", "CVE-2015-7756");
  script_bugtraq_id(79626);
  script_osvdb_id(132010, 132011);
  script_xref(name:"JSA", value:"JSA10713");
  script_xref(name:"CERT", value:"640184");

  script_name(english:"Juniper ScreenOS 6.2.x < 6.2.0r19 / 6.3.x < 6.3.0r21 Multiple Vulnerabilities (JSA10713)");
  script_summary(english:"Checks version of ScreenOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Juniper ScreenOS that is 6.2.x
prior to 6.2.0r19 or 6.3.x prior to 6.3.0r21. It is, therefore,
affected by multiple vulnerabilities :

  - A backdoor exists that allows a remote attacker
    administrative access to the device over SSH or telnet.
    (CVE-2015-7755)

  - An unspecified flaw exists that allows a
    man-in-the-middle attacker to decrypt VPN traffic.
    (CVE-2015-7756)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://kb.juniper.net/InfoCenter/index?page=content&id=JSA10713");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Juniper ScreenOS 6.2.0r19 / 6.3.0r21 or later.
Alternatively, apply the appropriate patch referenced in the vendor
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/12/17");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/18");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:juniper:screenos");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

display_fix = "";

# Fixes: 6.2.0r19, 6.3.0r21
if (version =~ "^6\.2([^0-9]|$)" && ver_compare(ver:version, fix:"6.2.0.19", strict:FALSE) == -1)
  display_fix = "6.2.0r19";
else if (version =~ "^6\.3([^0-9]|$)" && ver_compare(ver:version, fix:"6.3.0.21", strict:FALSE) == -1)
{
  if(version =~ "^6\.3\.0\.1[2-9](\.0)?$")
  {
    if((respin_version !~ "^[b-z]" && !isnull(respin_version)) || isnull(respin_version))
      display_fix = "6.3.0r1" + version[7] + "b";
  }
  else display_fix = "6.3.0r21";
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
