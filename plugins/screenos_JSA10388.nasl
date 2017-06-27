#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74365);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/13 15:33:29 $");

  script_cve_id("CVE-2008-6096");
  script_bugtraq_id(31528);
  script_osvdb_id(48670);

  script_name(english:"Juniper ScreenOS < 5.4.0r10 / 6.0 < 6.0.0r6 / 6.1 < 6.1.0r2 Web Interface and Telnet Login Pages XSS (JSA10388)");
  script_summary(english:"Checks version of ScreenOS.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Juniper ScreenOS prior to
5.4.0r10 / 6.0.0r6 / 6.1.0r2. It is, therefore, affected by a
cross-site scripting vulnerability due to improperly sanitizing user
input to the web interface and telnet login pages. An attacker could
exploit this vulnerability by tricking a user into requesting a
maliciously crafted URL, resulting in arbitrary script code execution.");
  script_set_attribute(attribute:"see_also", value:"http://kb.juniper.net/InfoCenter/index?page=content&id=JSA10388");
  script_set_attribute(attribute:"see_also", value:"https://www.juniper.net/security/auto/vulnerabilities/vuln31528.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to 5.4.0r10 / 6.0.0r6 / 6.1.0r2 or later or refer to the
vendor for a workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/10/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:screenos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("screenos_version.nbin");
  script_require_keys("Host/Juniper/ScreenOS/display_version", "Host/Juniper/ScreenOS/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

kb_base  = "Host/Juniper/ScreenOS/";
display_version = get_kb_item_or_exit(kb_base + "display_version");
version = get_kb_item_or_exit(kb_base + "version");

app_name = "Juniper ScreenOS";
display_fix = NULL;

if (version =~ "^[0-4]\." || version =~ "^5\.[0-3]([^0-9]|$)")
  display_fix = "5.4.0r10";
else if (version =~ "^5\.4([^0-9]|$)" && ver_compare(ver:version, fix:"5.4.0.10", strict:FALSE) == -1)
  display_fix = "5.4.0r10";
else if (version =~ "^6\.0([^0-9]|$)" && ver_compare(ver:version, fix:"6.0.0.6", strict:FALSE) == -1)
  display_fix = "6.0.0r6";
else if (version =~ "^6\.1([^0-9]|$)" && ver_compare(ver:version, fix:"6.1.0.2", strict:FALSE) == -1)
  display_fix = "6.1.0r2";

if (!isnull(display_fix))
{
  port = 0;
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

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
