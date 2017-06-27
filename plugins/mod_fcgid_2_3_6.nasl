#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54607);
  script_version('$Revision: 1.9 $');
  script_cvs_date("$Date: 2016/05/16 14:12:49 $");

  script_cve_id("CVE-2010-3872");
  script_bugtraq_id(44900);
  script_osvdb_id(69275);

  script_name(english:"Apache mod_fcgid Module fcgid_header_bucket_read() Function Remote Stack Buffer Overflow");
  script_summary(english:"Banner check to find vulnerable versions of mod_fcgid");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is at risk of a buffer overflow attack.");

  script_set_attribute(attribute:"description", value:
"According to its self-reported banner, the Apache web server listening
on this port includes a version of the mod_fcgid module earlier than
2.3.6.  As such, it has a stack-based buffer overflow vulnerability
because of an error in the pointer arithmetic used in the
'fcgid_header_bucket_read()' function.

An unauthenticated, remote attacker can leverage this with a specially
crafted request to overwrite data on the stack, leading to an
application crash or possibly even arbitrary code execution subject to
the privileges under which the web server operates.");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/bugzilla/show_bug.cgi?id=49406");
  # http://mail-archives.apache.org/mod_mbox/httpd-announce/201011.mbox/%3CAANLkTi=pWJ2KYDKuSFJDmnKd_xnF+S+_SZFn0esR-BjN@mail.gmail.com%3E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?012dfc54");
  script_set_attribute(attribute:"solution", value:"Update to version 2.3.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:mod_fcgid");
  script_end_attributes();

  script_family(english:"Web Servers");
  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/http", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

server = http_server_header(port:port);
if (isnull(server)) exit(0, "The web server listening on port "+port+" does not send a Server response header.");
if ("mod_fcgid" >!< server) exit(0, "The banner from the web server on port "+port+" does not mention mod_fcgid.");

match = eregmatch(string:server, pattern:"mod_fcgid/([0-9.]+)");
if (!match) exit(1, "The banner from the web server on port "+port+" does not include the mod_fcgid version.");
version = match[1];

if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixed_version = "2.3.6";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : ' + server +
      '\n  Installed version  : ' + version +
      '\n  Fixed version      : ' + fixed_version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The web server on port "+port+" appears to be using mod_fcgid "+version+" and thus is not affected.");
