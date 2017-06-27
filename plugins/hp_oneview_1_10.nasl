#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76776);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id("CVE-2010-5298", "CVE-2014-0198", "CVE-2014-0224");
  script_bugtraq_id(66801, 67193, 67899);
  script_osvdb_id(105763, 106531, 107729);
  script_xref(name:"CERT", value:"978508");
  script_xref(name:"HP", value:"emr_na-c04368264");
  script_xref(name:"HP", value:"HPSBGN03068");
  script_xref(name:"HP", value:"SSRT101004");

  script_name(english:"HP OneView < 1.10 OpenSSL Multiple Vulnerabilities (HPSBGN03068)");
  script_summary(english:"Checks the version of HP OneView.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by
multiple OpenSSL related vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of HP OneView installed on the remote host is 1.0, 1.01,
or 1.05. It is, therefore, affected by the following vulnerabilities
related to the included OpenSSL libraries :

  - An error exists in the function 'ssl3_read_bytes'
    that could allow data to be injected into other
    sessions or allow denial of service attacks. Note
    this issue is only exploitable if
    'SSL_MODE_RELEASE_BUFFERS' is enabled. (CVE-2010-5298)

  - An error exists in the function 'do_ssl3_write' that
    could allow a NULL pointer to be dereferenced leading
    to denial of service attacks. Note this issue is
    exploitable only if 'SSL_MODE_RELEASE_BUFFERS' is
    enabled. (CVE-2014-0198)

  - An unspecified error exists that could allow an
    attacker to cause usage of weak keying material
    leading to simplified man-in-the-middle attacks.
    (CVE-2014-0224)");
  # https://h20564.www2.hpe.com/portal/site/hpsc/public/kb/docDisplay?docId=emr_na-c04368264
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4400eebb");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/532783/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to HP OneView 1.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:oneview");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_oneview_detect.nbin");
  script_require_keys("www/hp_oneview");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443);

install = get_install_from_kb(appname:'hp_oneview', port:port, exit_on_fail:TRUE);

appname = 'HP OneView';
dir = install['dir'];
install_loc = build_url(port:port, qs:dir + "/");

version = install["ver"];
if (version == UNKNOWN_VER)  audit(AUDIT_UNKNOWN_WEB_APP_VER, appname, install_loc);

if ('build' >< version)
{
  ver = version - strstr(version, ' build');
}

if (
  ver =~ '^1\\.0(0)?$' ||
  ver =~ '^1\\.01$' ||
  ver =~ '^1\\.05$'
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_loc +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : 1.10\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_loc, ver);
