#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90940);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/13 15:33:29 $");

  script_osvdb_id(137894);

  script_name(english:"Juniper ScreenOS 6.3.x < 6.3.0r4 Firewall Private Address Information Disclosure");
  script_summary(english:"Checks the version of ScreenOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Juniper ScreenOS running on the remote host is 6.3.x
prior to 6.3.0r4. It is, therefore, affected by an information
disclosure vulnerability that allows an unauthenticated, remote
attacker to gain access to the private address of the firewall.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://www.juniper.net/techpubs/software/screenos/screenos6.3.0/rn-630-r4.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e28325ad");
  # http://www.juniper.net/techpubs/en_US/screenos6.3.0/information-products/pathway-pages/screenos/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4eb1929");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Juniper ScreenOS version 6.3.0r4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2010/07/13");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/06");

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

display_fix = NULL;

# 6.3.0r3 and prior are affected. 6.2 unsupported.
# fix is 6.3.0r4 and later
if (version =~ "^6\.3([^0-9]|$)" && ver_compare(ver:version, fix:"6.3.0.3", strict:FALSE) <= 0)
{
  display_fix = "6.3.0r4";
}

if(display_fix)
{
  port = 0;

  report = report_items_str(
    report_items:make_array(
      "Installed version", display_version,
      "Fixed version", display_fix
    ),
    ordered_fields:make_list("Installed version", "Fixed version")
  );
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);
