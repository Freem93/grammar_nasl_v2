#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88840);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/02/19 14:53:29 $");

  script_cve_id("CVE-2014-8618");
  script_bugtraq_id(74678);
  script_osvdb_id(121677);

  script_name(english:"Fortinet FortiADC Model D < 4.2 Theme Login Page XSS");
  script_summary(english:"Checks version of FortiADC.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote FortiADC Model D device is running a software version less
than 4.2. It is, therefore, affected by a cross-site scripting
vulnerability due to improper validation of user-supplied input to the
theme login page. An attacker can exploit this, via a specially
crafted request, to execute arbitrary script code in a user's browser
session.");
  script_set_attribute(attribute:"see_also", value:"http://www.fortiguard.com/advisory/FG-IR-15-005");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiADC version 4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/02/25");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/18");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:fortinet:fortiadc_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "FortiADC";

version = get_kb_item_or_exit("Host/Fortigate/version");
model = get_kb_item_or_exit("Host/Fortigate/model");

fix = "4.2";

# Make sure device is FortiADC D Model
if (!preg(string:model, pattern:"fortiadc-[0-9]*d($|[^a-z])", icase:TRUE)) audit(AUDIT_HOST_NOT, "a FortiADC D Model");

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  set_kb_item(name:"www/0/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(extra:report, port:0);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
