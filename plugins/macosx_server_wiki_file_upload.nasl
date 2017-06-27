#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(45441);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/04/21 16:17:30 $");

  script_cve_id("CVE-2010-0523");
  script_bugtraq_id(39289);
  script_osvdb_id(63370);

  script_name(english:"Apple Mac OS X Wiki Server File Upload Security Bypass");
  script_summary(english:"Queries the version of Mac OS X Web Services");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X Server Web Services installation contains a
version of the Wiki Server component that is affected by a security
bypass vulnerability due to allowing users to upload active content
such as Java applets. A remote attacker can exploit this flaw to
compromise the systems of legitimate users visiting the website or
possibly the remote server itself.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4077");
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2010/Mar/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/advisories/19364"
  );
  script_set_attribute(attribute:"solution", value:"Install Security Update 2010-002 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_server_web_svcs_version.nasl");
  script_require_keys("www/macosx_web_svcs_srv");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);
installs = get_install_from_kb(port:port, appname:"macosx_web_svcs_srv", exit_on_fail:TRUE);

v = installs['ver'];
if ( isnull(v) || v == UNKNOWN_VER ) exit(0, "An unknown version is installed on port "+port+".");

# 146.1
if ( int(v) > 0 && (int(v) < 146 || v == "146" ) ) security_warning(port);
else exit(0, "Version "+v+" is installed and not affected.");
