#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88593);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/16 16:21:30 $");

  script_cve_id("CVE-2015-3194");
  script_bugtraq_id(78623);
  script_osvdb_id(131038);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151204-openssl");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux41352");

  script_name(english:"Cisco Security Manager 4.9.x < 4.9(0.397) / 4.10.x < 4.10(0.189) OpenSSL ASN.1 Signature Handling DoS");
  script_summary(english:"Checks the version of Cisco Security Manager Web Server.");

  script_set_attribute(attribute:"synopsis", value:
"The web application running on the remote web server is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Security Manager running on the remote web server
is 4.9.x prior to 4.9(0.397) or 4.10.x prior to 4.10(0.189). It is,
therefore, affected by a NULL pointer dereference flaw in file
rsa_ameth.c due to improper handling of ASN.1 signatures that are
missing the PSS parameter. A remote attacker can exploit this to cause
the signature verification routine to crash, resulting in a denial of
service condition.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151204-openssl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4099a8d6");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCux41352");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20151203.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Security Manager version 4.9(0.397) / 4.10(0.189) or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:security_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_security_manager_http_detect.nbin");
  script_require_keys("Settings/ParanoidReport", "installed_sw/Cisco Security Manager");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

www_name = "Cisco Security Manager";

get_install_count(app_name:www_name, exit_if_zero:TRUE);
port = get_http_port(default:443);
if (!port) port = 443;

install = get_single_install(app_name:www_name, port:port, exit_if_unknown_ver:TRUE);

ver = install['version'];
path = install['path'];

fix = '';

if (ver =~ "^4\.10" && (ver_compare(ver:ver, fix:'4.10.0.189', strict:FALSE) < 0))
  fix = '4.10(0.189)';

else if (ver_compare(ver:ver, fix:'4.9.0.397', strict:FALSE) < 0)
  fix = '4.9(0.397)';

if (!empty(fix))
{
  if (report_verbosity > 0)
  {
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, www_name, ver, path);
