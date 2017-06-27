#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33104);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2008-4193");
  script_bugtraq_id(29457);
  script_xref(name:"EDB-ID", value:"5718");
  script_xref(name:"OSVDB", value:"45854");
  script_xref(name:"Secunia", value:"30497");

  script_name(english:"SecurityGateway < 1.0.2 Administration Interface username Field Remote Overflow");
  script_summary(english:"Grabs version from the Server response header");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Alt-N's SecurityGateway for Exchange/SMTP,
an email spam firewall for Exchange and SMTP servers. 

The version of SecurityGateway installed on the remote host is earlier
than 1.0.2.  Such versions are reportedly affected by a buffer
overflow that can be triggered using a long 'username' parameter to
the 'SecurityGateway.dll' script to execute arbitrary code on the
remote host with SYSTEM-level privileges, potentially resulting in a
complete compromise of the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://files.altn.com/SecurityGateway/Release/relnotes_en.htm" );
 script_set_attribute(attribute:"see_also", value:"http://lists.altn.com/WebX/.eedd95a?50@661.aj7ZavbDPBD@" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SecurityGateway 1.0.2 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Alt-N SecurityGateway username Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/06/06");
 script_cvs_date("$Date: 2016/05/19 18:02:18 $");
 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 4000, 4443);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:4000, embedded: 1);

# Check the version in the banner.
banner = get_http_banner(port:port, exit_on_fail: 1);

banner = strstr(banner, "Server:");
banner = banner - strstr(banner, '\r\n');
if ("ALT-N SecurityGateway " >< banner)
{
  version = strstr(banner, "ALT-N SecurityGateway ") - "ALT-N SecurityGateway ";
  if (version =~ "^(0\.|1\.0\.[01]($|[^0-9]))")
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "SecurityGateway version ", version, " appears to be installed on the\n",
        "remote host.\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
}
