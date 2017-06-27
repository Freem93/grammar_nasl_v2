#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83877);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/11/01 04:40:10 $");

  script_cve_id(
    "CVE-2014-9293",
    "CVE-2014-9294",
    "CVE-2014-9295",
    "CVE-2014-9296"
  );
  script_bugtraq_id(
    71757,
    71758,
    71761,
    71762
  );
  script_osvdb_id(
    116066,
    116067,
    116068,
    116069,
    116070,
    116074
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCus27300");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20141222-ntpd");
  script_xref(name:"CERT", value:"852879");

  script_name(english:"Cisco Prime LAN Management Solution ntpd Multiple Vulnerabilities");
  script_summary(english:"Checks the Cisco Prime LMS version.");

  script_set_attribute(attribute:"synopsis", value:
"A network management system on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Cisco Prime LAN
Management Solution running on the remote host is affected by multiple
vulnerabilities :

  - A security weakness exists due to the config_auth()
    function improperly generating default keys when no
    authentication key is defined in the 'ntp.conf' file.
    Key size is limited to 31 bits and the insecure
    ntp_random() function is used, resulting in
    cryptographically weak keys with insufficient entropy.
    This allows a remote attacker to defeat cryptographic
    protection mechanisms via a brute-force attack.
    (CVE-2014-9293)

  - A security weakness exists due the use of a weak seed
    to prepare a random number generator used to generate
    symmetric keys. This allows remote attackers to defeat
    cryptographic protection mechanisms via a brute-force
    attack. (CVE-2014-9294)

  - Multiple stack-based buffer overflows exist due to
    improperly validated user-supplied input when handling
    packets in the crypto_recv(), ctl_putdata(), and
    configure() functions when using autokey authentication.
    This allows a remote attacker, via a specially crafted
    packet, to cause a denial of service condition or
    execute arbitrary code. (CVE-2014-9295)

  - A unspecified vulnerability exists due to missing return
    statements in the receive() function, resulting in
    continued processing even when an authentication error
    is encountered. This allows a remote attacker, via
    crafted packets, to trigger unintended association
    changes. (CVE-2014-9296)");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20141222-ntpd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?79cfbf7f");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cisco Prime LMS 4.2(5.3) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_lan_management_solution");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_prime_lms_web_detect.nasl");
  script_require_ports("Services/www", 443);
  script_require_keys("www/cisco_lms", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("http.inc");
include("install_func.inc");

get_install_count(app_name:"cisco_lms", exit_if_zero:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:443);
app = "Cisco Prime LAN Management Solution";

install = get_single_install(
  app_name : "cisco_lms",
  port     : port,
  exit_if_unknown_ver : TRUE
);
version = install["version"];
path = install["path"];
url = build_url(port:port, qs:path);

if (cisco_gen_ver_compare(a:version, b:'4.2(5.3)') == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 4.2(5.3)' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);
