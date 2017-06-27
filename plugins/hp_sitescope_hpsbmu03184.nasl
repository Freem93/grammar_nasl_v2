#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79719);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/21 22:04:46 $");

  script_cve_id("CVE-2014-3566");
  script_bugtraq_id(70574);
  script_osvdb_id(113251);
  script_xref(name:"CERT", value:"577193");
  script_xref(name:"HP", value:"emr_na-c04497114");
  script_xref(name:"HP", value:"HPSBMU03184");
  script_xref(name:"HP", value:"SSRT101794");

  script_name(english:"HP SiteScope SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)");
  script_summary(english:"Checks the version of HP SiteScope.");

  script_set_attribute(attribute:"synopsis", value:
"A web application installed on the remote host is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP SiteScope installed on the remote host is affected
by a man-in-the-middle (MitM) information disclosure vulnerability
known as POODLE. The vulnerability is due to the way SSL 3.0 handles
padding bytes when decrypting messages encrypted using block ciphers
in cipher block chaining (CBC) mode. MitM attackers can decrypt a
selected byte of a cipher text in as few as 256 tries if they are able
to force a victim application to repeatedly send the same data over
newly created SSL 3.0 connections.");
  # https://softwaresupport.hpe.com/group/softwaresupport/search-result/-/facetsearch/document/KM01227923
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?51dd699d");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04497114
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5c01f59");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Refer to the instructions in vendor support document KM01227923 for
steps to disable SSLv3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:TF/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:sitescope");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_sitescope_detect.nasl", "ssl_poodle.nasl");
  script_require_keys("www/sitescope");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("webapp_func.inc");
include("http.inc");

port = get_http_port(default:8080);

install = get_install_from_kb(appname:'sitescope', port:port, exit_on_fail:TRUE);
version = install['ver'];
dir     = install['dir'];
vuln    = FALSE;

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, 'HP SiteScope', build_url(port:port, qs:dir));

if (version =~ "^11\.[12]\d($|[^0-9])")
{
  vuln = TRUE;
  # If not paranoid, do not report if not
  # vuln to real POODLE check
  if (report_paranoia < 2 && !get_kb_item("SSL/vulnerable_to_poodle/"+port))
    vuln = FALSE;
}

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + build_url(port:port, qs:dir) +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : See solution.' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'HP SiteScope',  build_url(port:port, qs:dir), version);
