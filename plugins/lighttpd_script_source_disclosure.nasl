#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(21155);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2006-0814");
  script_bugtraq_id(16893);
  script_osvdb_id(23542);

  script_name(english:"lighttpd on Windows < 1.4.10a Crafted Filename Request Script Source Disclosure");
  script_summary(english:"Checks version of lighttpd.");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of lighttpd running on the remote
Windows host is prior to 1.4.10a. It is, therefore, affected by an
information disclosure vulnerability due to a failure to properly
validate filename extensions in URLs. A remote attacker can exploit
this issue, via specially crafted requests with dot and space
characters, to disclose the source of scripts hosted by the affected
application.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2006-9/advisory/" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to lighttpd for Windows version 1.4.10a or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/27");
  script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/01");

  script_cvs_date("$Date: 2016/06/21 19:27:16 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:lighttpd:lighttpd");
  script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if (
  banner &&
  egrep(pattern:"^Server: lighttpd/1\.4\.([0-9][^0-9]?|10) \(Win32\)", string:banner)
) security_warning(port);
