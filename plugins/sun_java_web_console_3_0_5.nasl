#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31423);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2008-1286");
  script_bugtraq_id(28155);
  script_osvdb_id(42703);
  script_xref(name:"Secunia", value:"29290");

  script_name(english:"Sun Java Web Console < 3.0.5 Remote File Enumeration");
  script_summary(english:"Retrieves version info");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Sun Java Web Console on
the remote host may allow a local or remote unprivileged user to
determine the existence of files or directories in access restricted
directories, which could result in a loss of confidentiality." );
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1018987.1.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as discussed in the vendor advisory above." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"patch_publication_date", value: "2008/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value: "2008/03/13");
  script_set_attribute(attribute:"plugin_type", value: "remote");
  script_set_attribute(attribute:"cpe", value: "cpe:/a:sun:java_web_console");
  script_cvs_date("$Date: 2016/05/17 17:13:10 $");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 6788, 6789);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


# Only Linux and Solaris are affected according to Sun.
if (report_paranoia < 2)
{
  os = get_kb_item("Host/OS");
  if ("Linux" >!< os && "Solaris" >!< os) exit(0);
}


port = get_http_port(default:6788);

# Make sure it's Sun Java Web Console.
banner = http_get_cache(port:port, item: "/", exit_on_fail: 1);

redirect = strstr(banner, "Location:");
if (strlen(redirect)) redirect = redirect - strstr(redirect, '\r\n');
if (strlen(redirect) == 0 || "login/BeginLogin.jsp" >!< redirect) exit(0);


# Try to retrieve the version number.
w = http_send_recv3(method:"GET", item:"/console/html/en/console_version.shtml", port:port, exit_on_fail: 1);
res = w[2];

if (
  "title>Sun Java(TM) Web Console: Version<" >< res &&
  '"VrsHdrTxt">Version ' >< res
)
{
  version = strstr(res, '"VrsHdrTxt">Version ') - '"VrsHdrTxt">Version ';
  if (strlen(version)) version = version - strstr(version, '</div');

  # nb: Sun only talks about 3.0.2, 3.0.3, and 3.0.4 as affected.
  if (strlen(version) && version =~ "^3\.0\.[2-4]($|[^0-9])")
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "Sun Java Web Console version ", version, " is installed on the remote host.\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}

