#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73528);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/04/23 20:09:18 $");

  script_cve_id("CVE-2014-1955", "CVE-2014-1956", "CVE-2014-1957");
  script_bugtraq_id(65660);
  script_osvdb_id(103449, 103450, 103451);

  script_name(english:"Fortinet FortiWeb 4.x / 5.x < 5.0.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of FortiWeb");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running FortiWeb 4.x / 5.x prior to 5.0.3. It is,
therefore, affected by multiple vulnerabilities :

  - FortiWeb is affected by a cross-site scripting
    vulnerability due to a failure to sanitize
    user-supplied input. (CVE-2014-1955)

  - FortiWeb is affected by an unspecified HTTP header
    injection vulnerability. (CVE-2014-1956)

  - FortiWeb is affected by an unspecified privilege
    escalation vulnerability. (CVE-2014-1957)");
  script_set_attribute(attribute:"see_also", value:"http://www.fortiguard.com/advisory/FG-IR-13-009");
  script_set_attribute(attribute:"solution", value:"Upgrade to Fortinet FortiWeb 5.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortiweb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "FortiWeb";
model = get_kb_item_or_exit("Host/Fortigate/model");
version = get_kb_item_or_exit("Host/Fortigate/version");

# Make sure device is FortiWeb.
if (!preg(string:model, pattern:"fortiweb", icase:TRUE)) audit(AUDIT_HOST_NOT, "a " + app_name + " device");

# Only 4.x and 5.x are is affected. Same fix for both.
if (version =~ "^5\." || version =~ "^4\.") fix = "5.0.3";
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = 0;
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';

    security_warning(extra:report, port:port);
  }
  else security_warning(port:port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
