#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91260);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/20 14:03:00 $");

  script_osvdb_id(138445);
  script_xref(name:"TRA", value:"TRA-2016-14");

  script_name(english:"HP System Management Homepage < 7.5.4.3 AddCertsToTrustCfgList DoS");
  script_summary(english:"Checks the version of HP System Management Homepage.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP System Management Homepage (SMH) hosted on the
remote web server is prior to 7.5.4.3. It is, therefore, affected by a
flaw in the AddCertsToTrustCfgList() function within
file mod_smh_config.so due to improper extraction of the common name
in the subject when processing X.509 certificates. An unauthenticated,
remote attacker can exploit this issue, via a crafted certificate, to
cause a denial of service condition. Note that to exploit this
vulnerability, the 'Trust Mode' setting must be configured with
'Trust All', the 'IP Restricted login' setting must allow the attacker
to access SMH, and the 'Kerberos Authorization' (Windows only) setting
must be disabled.");
  script_set_attribute(attribute:"see_also", value:"http://www.tenable.com/security/research/tra-2016-14");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP System Management Homepage (SMH) version 7.5.4.3 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:system_management_homepage");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("compaq_wbem_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("www/hp_smh", "Settings/ParanoidReport");
  script_require_ports("Services/www", 2301, 2381);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

get_kb_item_or_exit("www/hp_smh");

# Only Linux and Windows are affected -- HP-UX is not mentioned, new releases
# for HP-UX are not available/published
# http://www8.hp.com/ca/en/products/server-software/product-detail.html?oid=344313
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

port    = get_http_port(default:2381, embedded:TRUE);

install = get_install_from_kb(appname:'hp_smh', port:port, exit_on_fail:TRUE);
dir     = install['dir'];
version = install['ver'];
prod    = get_kb_item_or_exit("www/"+port+"/hp_smh/variant");

if (version == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_APP_VER, "HP System Management Homepage");

# nb: 'version' can have non-numeric characters in it so we'll create
#     an alternate form and make sure that's safe for use in 'ver_compare()'.
version_alt = ereg_replace(pattern:"[_-]", replace:".", string:version);
if (!ereg(pattern:"^[0-9][0-9.]+$", string:version_alt))
  audit(AUDIT_VER_FORMAT, version_alt);

fixed_version = '7.5.4.3';

if (ver_compare(ver:version_alt, fix:fixed_version, strict:FALSE) < 0)
{
  source_line = get_kb_item("www/"+port+"/hp_smh/source");

  report = '\n  Product           : ' + prod;
  if (!isnull(source_line))
    report += '\n  Version source    : ' + source_line;
  report +=
    '\n  Installed version : ' + version_alt +
    '\n  Fixed version     : ' + fixed_version +
    '\n';

  security_report_v4(severity:SECURITY_NOTE, port:port, extra:report);
}
else
  audit(AUDIT_LISTEN_NOT_VULN, prod, port, version);
