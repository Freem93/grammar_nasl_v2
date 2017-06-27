#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70682);
  script_version('$Revision: 1.3 $');
  script_cvs_date("$Date: 2014/05/24 02:15:09 $");

  script_cve_id("CVE-2013-4365");
  script_bugtraq_id(62939);
  script_osvdb_id(98300);

  script_name(english:"Apache mod_fcgid Module < 2.3.9 fcgid_header_bucket_read() Function Heap-Based Buffer Overflow");
  script_summary(english:"Banner check to find vulnerable versions of mod_fcgid");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a buffer overflow
vulnerability.");

  script_set_attribute(attribute:"description", value:
"According to its self-reported banner, the Apache web server listening
on this port includes a version of the mod_fcgid module earlier than
2.3.9.  That reportedly has a heap-based buffer overflow vulnerability
because of an error in the pointer arithmetic used in the
'fcgid_header_bucket_read()' function.");
  script_set_attribute(attribute:"see_also", value:"http://www.mail-archive.com/dev@httpd.apache.org/msg58077.html");
  # https://mail-archives.apache.org/mod_mbox/httpd-cvs/201309.mbox/%3C20130929174048.13B962388831@eris.apache.org%3E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08112f11");
  script_set_attribute(attribute:"solution", value:"Update to version 2.3.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:mod_fcgid");
  script_end_attributes();

  script_family(english:"Web Servers");
  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

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

fixed_version = "2.3.9";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + server +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + 
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The web server on port "+port+" appears to be using mod_fcgid "+version+" and thus is not affected.");
