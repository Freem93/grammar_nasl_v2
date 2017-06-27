#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68994);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/03/02 14:34:37 $");

  script_cve_id("CVE-2010-5192");
  script_bugtraq_id(43675);
  script_osvdb_id(68322);

  script_name(english:"Blue Coat ProxySG Unspecified XSS");
  script_summary(english:"Checks the Blue Coat ProxySG SGOS version");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a cross-site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Blue Coat ProxySG device's SGOS self-reported version is
earlier than 4.3.4.1, 5.3.x/5.4.x earlier than 5.4.5.1, 5.5.x earlier
than 5.5.4.1 or 6.x earlier than 6.1.1.1.  It is, therefore, reportedly
affected by an unspecified cross-site scripting vulnerability.");
  # Security advisory SA47
  script_set_attribute(attribute:"see_also", value:"https://kb.bluecoat.com/index?page=content&id=SA47");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 4.3.4.1 / 5.4.5.1 / 6.1.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:bluecoat:sgos");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Firewalls");

  script_dependencies("bluecoat_proxy_sg_version.nasl");
  script_require_keys("Host/BlueCoat/ProxySG/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version    = get_kb_item_or_exit("Host/BlueCoat/ProxySG/Version");
ui_version = get_kb_item("Host/BlueCoat/ProxySG/UI_Version");

if (version =~ "^4\.3\.")
{
  fix    = '4.3.4.1';
  ui_fix = '4.3.4.1 Build 0';
}
else if (version =~ "^5\.[0-3]\." || version =~ "^5\.4\.")
{
  fix    = '5.4.5.1';
  ui_fix = '5.4.5.1 Build 0';
}
else if (version =~ "^5\.5\.")
{
  fix    = '5.5.4.1';
  ui_fix = '5.5.4.1 Build 0';
}
else if (version =~ "^6\.")
{
  fix    = '6.1.1.1';
  ui_fix = '6.1.1.1 Build 0';
}
# If very low version (0.x - 4.2.x) just recommend latest update
else
{
  fix    = '6.1.1.1';
  ui_fix = '6.1.1.1 Build 0';
}

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    # Select format for output
    if (isnull(ui_version))
    {
      report_ver = version;
      report_fix = fix;
    }
    else
    {
      report_ver = ui_version;
      report_fix = ui_fix;
    }

    report =
      '\n  Installed version : ' + report_ver +
      '\n  Fixed version     : ' + report_fix +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
