#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68993);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/03/15 02:06:32 $");

  script_cve_id("CVE-2011-5126");
  script_bugtraq_id(48336);
  script_osvdb_id(73238);

  script_name(english:"Blue Coat ProxySG Core File Information Disclosure");
  script_summary(english:"Checks the Blue Coat ProxySG SGOS version");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is potentially affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Blue Coat ProxySG device's SGOS self-reported version is
6.1.x earlier than 6.1.5.1 or 6.2.x earlier than 6.2.2.1.  It is,
therefore, potentially affected by an information disclosure
vulnerability. 

Exported core files are unencrypted, contain sensitive information
and could be used to aid in further attacks.");
  # Security advisory SA47
  script_set_attribute(attribute:"see_also", value:"https://kb.bluecoat.com/index?page=content&id=SA56");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 6.1.5.1 / 6.2.2.1 or later and delete existing,
unneeded core files.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:bluecoat:sgos");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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

if (version =~ "^6\.1\.")
{
  fix    = '6.1.5.1';
  ui_fix = '6.1.5.1 Build 0';
}
else if (version =~ "^6\.2\.")
{
  fix    = '6.2.2.1';
  ui_fix = '6.2.2.1 Build 0';
}
else audit(AUDIT_HOST_NOT, "affected");

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
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
    security_note(port:0, extra:report);
  }
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
