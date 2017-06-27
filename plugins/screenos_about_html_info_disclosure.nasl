#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74366);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/06 18:38:46 $");

  script_bugtraq_id(34710);
  script_osvdb_id(56005);

  script_name(english:"Juniper ScreenOS 5.4.x < 5.4.0r12 / 6.1.x / 6.2.x < 6.2.0r2 'about.html' Information Disclosure");
  script_summary(english:"Checks version of ScreenOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Juniper ScreenOS prior to
5.4.0r12 / 6.2.0r2. It is, therefore, affected by an information
disclosure vulnerability due to system information being displayed in
the 'about.html' page. A remote, unauthenticated attacker could
leverage this information to aid in further attacks.");
  script_set_attribute(attribute:"see_also", value:"https://www.juniper.net/security/auto/vulnerabilities/vuln34710.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/502958");
  # http://www.procheckup.com/vulnerability_manager/vulnerabilities/pr09-05
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3496f575");
  script_set_attribute(attribute:"solution", value:"Upgrade to 5.4.0r12 / 6.2.0r2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:screenos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("screenos_version.nbin");
  script_require_keys("Host/Juniper/ScreenOS/display_version", "Host/Juniper/ScreenOS/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base  = "Host/Juniper/ScreenOS/";
display_version = get_kb_item_or_exit(kb_base + "display_version");
version = get_kb_item_or_exit(kb_base + "version");

app_name = "Juniper ScreenOS";
display_fix = NULL;

if (version =~ "^5\.4([^0-9]|$)" && ver_compare(ver:version, fix:"5.4.0.12", strict:FALSE) == -1)
  display_fix = "5.4.0r12";
else if (version =~ "^6\.[12]([^0-9]|$)" && ver_compare(ver:version, fix:"6.2.0.2", strict:FALSE) == -1)
  display_fix = "6.2.0r2";

if (!isnull(display_fix))
{
  port = 0;
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + display_version +
      '\n  Fixed version     : ' + display_fix +
      '\n';

    security_warning(extra:report, port:port);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);
