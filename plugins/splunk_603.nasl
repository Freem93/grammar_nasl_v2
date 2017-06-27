#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73575);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/12 14:55:05 $");

  script_cve_id("CVE-2013-4353", "CVE-2014-0160");
  script_bugtraq_id(64691, 66690);
  script_osvdb_id(101843, 105465);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");

  script_name(english:"Splunk 6.x < 6.0.3 Multiple OpenSSL Vulnerabilities (Heartbleed)");
  script_summary(english:"Checks the version of Splunk.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by
multiple OpenSSL-related vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the Splunk Web hosted on the remote
web server is 6.x prior to 6.0.3. It is, therefore, affected by
multiple OpenSSL-related vulnerabilities :

  - A flaw exists with the OpenSSL version being used by
    Splunk with the 'ssl3_take_mac' in 'ssl/s3_both.c'. This
    allows a remote attacker to cause a denial of service
    with a specially crafted request. (CVE-2013-4353)

  - An out-of-bounds read error, known as Heartbleed, exists
    in the TLS/DTLS implementation due to improper handling
    of TLS heartbeat extension packets. A remote attacker,
    using crafted packets, can trigger a buffer over-read,
    resulting in the disclosure of up to 64KB of process
    memory, which contains sensitive information such as
    primary key material, secondary key material, and other
    protected content. (CVE-2014-0160)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.splunk.com/view/SP-CAAAMB3");
  script_set_attribute(attribute:"see_also", value:"http://docs.splunk.com/Documentation/Splunk/6.0.3/ReleaseNotes/6.0.3");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"http://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to Splunk 6.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("splunkd_detect.nasl","splunk_web_detect.nasl");
  script_require_ports("Services/www", 8089, 8000);
  script_require_keys("installed_sw/Splunk");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Splunk";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8000, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
ver = install['version'];

install_url = build_url(qs:dir, port:port);

if (ver =~ "^6\." && ver_compare(ver:ver,fix:"6.0.3",strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +ver+
      '\n  Fixed version     : 6.0.3\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, ver);
