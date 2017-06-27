#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65688);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/07 18:43:41 $");

  script_cve_id("CVE-2011-4696");
  script_bugtraq_id(57163);
  script_osvdb_id(88914);

  script_name(english:"Eye-Fi Helper < 3.4.23 Directory Traversal");
  script_summary(english:"Checks version of Eye-Fi Helper");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a
directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Eye-Fi Helper installed on the remote host is a version
prior to 3.4.23.  It is, therefore, affected by a directory traversal
vulnerability because it fails to properly sanitize user- supplied
input. 

An attacker could exploit this issue to overwrite arbitrary files on the
vulnerable computer, which could result in a denial of service or
arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"http://www.pentest.co.uk/documents/ptl-2013-01.html");
  script_set_attribute(attribute:"see_also", value:"http://support.eye.fi/downloads/release-notes/center/");
  script_set_attribute(attribute:"solution", value:"Update to Eye-Fi Helper 3.4.23 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:eye:eye-fi_helper");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("eyefi_helper_detect.nasl");
  script_require_keys("www/eyefi_helper");
  script_require_ports("Services/www", 59278);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:59278);

install = get_install_from_kb(
  appname      : "eyefi_helper",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
version = install["ver"];
install_url = build_url(port:port, qs:install["dir"]);

appname = "Eye-Fi Helper";
fix = '3.4.23';

if(ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
        '\n  URL               : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, version);


