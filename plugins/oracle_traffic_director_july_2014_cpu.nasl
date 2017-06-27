#
# (C) Tenable Network Security, Inc.
#

appname = "Oracle Traffic Director";

include("compat.inc");

if (description)
{
  script_id(76938);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/09 18:30:47 $");

  script_cve_id(
    "CVE-2013-1739",
    "CVE-2013-1740",
    "CVE-2013-1741",
    "CVE-2013-5605",
    "CVE-2013-5606",
    "CVE-2014-1490",
    "CVE-2014-1491",
    "CVE-2014-1492"
  );
  script_bugtraq_id(
    62966,
    63736,
    63737,
    63738,
    64944,
    65332,
    65335,
    66356
  );
  script_osvdb_id(
    98402,
    99746,
    99747,
    99748,
    102170,
    102876,
    102877,
    104708
  );

  script_name(english:"Oracle Traffic Director Multiple Vulnerabilities (July 2014 CPU)");
  script_summary(english:"Checks for patched files.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is running software with multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running an unpatched version of Oracle Traffic
Director that is affected by the following vulnerabilities :

  - The implementation of Network Security Services (NSS)
    does not ensure that data structures are initialized,
    which could result in a denial of service or disclosure
    of sensitive information. (CVE-2013-1739)

  - The implementation of Network Security Services (NSS)
    does not properly handle the TLS False Start feature
    and could allow man-in-the-middle attacks.
    (CVE-2013-1740)

  - NSS contains an integer overflow flaw that allows
    remote attackers to cause a denial of service.
    (CVE-2013-1741)

  - An error exists in the 'Null_Cipher' function in the
    file 'ssl/ssl3con.c' related to handling invalid
    handshake packets that could allow arbitrary code
    execution. (CVE-2013-5605)

  - An error exists in the 'CERT_VerifyCert' function in
    the file 'lib/certhigh/certvfy.c' that could allow
    invalid certificates to be treated as valid.
    (CVE-2013-5606)

  - Network Security Services (NSS) contains a race
    condition in libssl that occurs during session ticket 
    processing. A remote attacker can exploit this flaw
    to cause a denial of service. (CVE-2014-1490)

  - Network Security Services (NSS) does not properly
    restrict public values in Diffie-Hellman key exchanges,
    allowing a remote attacker to bypass cryptographic
    protection mechanisms. (CVE-2014-1491)

  - An issue exists in the Network Security (NSS) library
    due to improper handling of IDNA domain prefixes for
    wildcard certificates. This issue could allow man-in-
    the-middle attacks. (CVE-2014-1492)");
  # http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7de2f8eb");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2014 Oracle Critical
Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:traffic_director");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("oracle_traffic_director_detect.nbin");
  script_require_keys("installed_sw/" + appname);
  script_require_ports("Services/www", 8989);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8989);

installs = get_installs(app_name:appname, port:port);

if (installs[0] != IF_OK) audit(AUDIT_WEB_APP_NOT_INST, appname, port);

# only one listening install per port / per host possible
install = installs[1][0];

version = install['version'];

install_url = build_url(port:port, qs:install['path']);

if (version !~ "^11\.1\.1\.7(\.0)?$") audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, version);

res1 = http_send_recv3(port:port,
                       method:'GET',
                       item:'/help/support/html/cpyr.htm',
                       exit_on_fail:TRUE);

res2 = http_send_recv3(port:port,
                       method:'GET',
                       item:'/js/dojo/td/postinit.js',
                       exit_on_fail:TRUE);

# check for unpatched files
if (
  "<h2>Copyright Notice</h2>" >< res1[2] &&
  res1[2] =~ "Copyright &copy; 1994-201[0-2], Oracle" &&
  "networkPrefixClass" >!< res2[2] &&
  '{"dijit/form/TextBox":function()' >< res2[2]
)
{
  if (report_verbosity > 0)
  {
    report = '\n  URL               : ' + install_url +
             '\n  Installed version : ' + version +
             '\n  Missing patch     : 18920619\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, version);
