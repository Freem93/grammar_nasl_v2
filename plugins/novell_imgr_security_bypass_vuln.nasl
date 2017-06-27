#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33867);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/11 13:40:20 $");

  script_cve_id("CVE-2008-3488");
  script_bugtraq_id(30497);
  script_osvdb_id(47278);
  script_xref(name:"Secunia", value:"31333");

  script_name(english:"Novell iManager < 2.7 SP1 Property Book Pages Arbitrary Plug-in Studio Deletion");
  script_summary(english:"Checks list of available NPMs");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a security bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"Novell iManager is installed on the remote host.  The version of
iManager installed reportedly fails to implement sufficient access
control checks on 'Property Book Pages' created with Plug-in Studio
before granting delete privileges on them to a user.");
  # http://support.novell.com/docs/Readmes/InfoDocument/patchbuilder/readme_5031820.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?225c9e63");
  script_set_attribute(attribute:"solution", value:"Upgrade to Novell iManager 2.7 SP1 (iManager 2.7.1).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/31");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("novell_imanager_detect.nasl");
  script_require_keys("www/novell_imanager");
  script_require_ports("Services/www", 8080, 8443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8080);
install = get_install_from_kb(appname:'novell_imanager', port:port, exit_on_fail:TRUE);

# Retrieve the list of Novell Plug-in Modules (NPMs).
url = "/nps/packages/iman_mod_desc.xml";

w = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

# Exit if the iManager NPM is not installed.
if ("<filename>iManager.npm</filename>" >!< w[2])
  audit(AUDIT_NOT_DETECT, "Novell iManager NPM", port);


# Determine its version number.
module = strstr(w[2], "<filename>iManager.npm</filename>");
module = module - strstr(module, "</module>");

version = "";
if (module && "<version>" >< module && "</version>" >< module)
{
  version = strstr(module, "<version>") - "<version>";
  version = version - strstr(version,'</version>');
}
if (!version) exit(1, "Failed to get the version of iManager NPM listening on port "+port+".");


# There's a problem if...
if (
  # it's a version < 2.7.0 or...
  version =~ "^([01]\.|2\.[0-6]\.)" ||
  # it's version 2.7.0 and there's no service pack.
  (
    version =~ "^2\.7\.0([^0-9]|$)" &&
    !egrep(pattern:"<description>Support Pack [0-9]+ for iManager 2\.7</description", string:w[2])
  )
)
{
  if (report_verbosity)
  {
    version = ereg_replace(
      pattern:"^([0-9]+\.[0-9]+\.[0-9]+)(\.[0-9]+)?$",
      replace:"\1",
      string:version
    );

    if (version =~ "^2\.7\.0([^0-9]|$)")
    {
      report = string(
        "\n",
        "Novell iManager version ", version, " is installed on the remote host\n",
        "without any Support Packs.\n"
      );
    }
    else
    {
      report = string(
        "\n",
        "Novell iManager version ", version, " is installed on the remote host.\n"
      );
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
