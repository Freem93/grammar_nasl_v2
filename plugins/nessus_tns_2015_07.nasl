#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86949);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/03/07 17:25:24 $");

  script_cve_id("CVE-2015-1788", "CVE-2015-1789");
  script_bugtraq_id(75156, 75158);
  script_osvdb_id(123172, 123173);

  script_name(english:"Nessus 5.x < 5.2.12 / 6.x < 6.4 Multiple OpenSSL Vulnerabilities");
  script_summary(english:"Checks the Nessus version.");

  script_set_attribute(attribute:"synopsis",value:
"The remote Nessus installation is affected by multiple denial of
service vulnerabilities in the bundled OpenSSL component.");
  script_set_attribute(attribute:"description",value:
"According to its version, the installation of Tenable Nessus running
on the remote host is version 5.x prior to 5.2.12 or 6.x prior to 6.4.
It is, therefore, affected by multiple denial of service
vulnerabilities in the bundled OpenSSL component :

  - A denial of service vulnerability exists when processing
    an ECParameters structure due to an infinite loop that
    occurs when a specified curve is over a malformed binary
    polynomial field. A remote attacker can exploit this to
    perform a denial of service against any system that
    processes public keys, certificate requests, or
    certificates. This includes TLS clients and TLS servers
    with client authentication enabled. (CVE-2015-1788)

  - A denial of service vulnerability exists due to improper
    validation of the content and length of the ASN1_TIME
    string by the X509_cmp_time() function. A remote
    attacker can exploit this, via a malformed certificate
    and CRLs of various sizes, to cause a segmentation
    fault, resulting in a denial of service condition. TLS
    clients that verify CRLs are affected. TLS clients and
    servers with client authentication enabled may be
    affected if they use custom verification callbacks.
    (CVE-2015-1789)");
  script_set_attribute(attribute:"see_also",value:"https://www.tenable.com/security/tns-2015-07");
  script_set_attribute(attribute:"see_also",value:"https://www.openssl.org/news/secadv/20150611.txt");
  script_set_attribute(attribute:"solution",value:
"Upgrade to Tenable Nessus 5.2.12 / 6.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/06/30");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/19");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:tenable:nessus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("nessus_detect.nasl");
  script_require_ports("Services/www", 8834);
  script_require_keys("installed_sw/nessus");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

app = "nessus";
get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:8834);

install = get_install_from_kb(appname:app, port:port, exit_on_fail:TRUE);
dir = install['dir'];
install_loc = build_url(port:port, qs:dir + '/');

version = install['ver'];
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Nessus", install_loc);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i < max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] < 5 ||
   (ver[0] == 6 && ver[1] < 4) ||
   (ver[0] == 5 && ver[1] != 2) ||
   (ver[0] == 5 && ver[1] == 2 && (isnull(ver[2]) || ver[2] < 12)))
{
  fix = "6.4";
  if(ver[0] == 5) fix += "/5.2.12";

  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version  : ' + version +
      '\n  Fixed version      : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Nessus", port, version); 
