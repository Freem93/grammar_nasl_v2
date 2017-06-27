#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(97994);
  script_version ("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/04/17 18:59:17 $");

  script_name(english:"Microsoft IIS 6.0 Unsupported Version Detection");
  script_summary(english: "Checks if IIS version is unsupported.");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of Microsoft IIS is running on the remote
Windows host.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Microsoft Internet Information Services (IIS) 6.0 on the remote host
is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # https://support.microsoft.com/en-us/lifecycle/search?alpha=Microsoft%20Internet%20Information%20Services%206.0
  script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?d99a8431");
  script_set_attribute(attribute:"see_also", value: "https://www.microsoft.com/en-us/cloud-platform/windows-server-2003");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Microsoft IIS that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/iis");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

get_kb_item_or_exit("www/iis");
port = get_http_port(default:80);

app = "Microsoft IIS";
banner = get_http_banner(port:port);
cpe_base= "microsoft:iis";

if (banner !~ "Server: Microsoft-IIS") audit(AUDIT_NOT_DETECT, app, port);
else banner = strstr(banner, "Server:"); # slice banner

# get IIS version
pat = "^Server: Microsoft-IIS\/([\d]+(?:\.[\d]+)+)";
version = pregmatch(string:banner, pattern:pat);
if (isnull(version)) audit(AUDIT_UNKNOWN_APP_VER, app);
else version = version[1];

# <= 6.0 is unsupported
if (ver_compare(ver:version, fix:'6.0', strict:FALSE) <= 0)
{
  register_unsupported_product(product_name:app, cpe_base:cpe_base, version:version ); 
  report =
    '\n  Installed version  : ' + version +
    '\n  Supported versions : 7.0 or later' +
    '\n  EOL date           : 2015/07/14' +
    '\n  EOL URL            : http://www.nessus.org/u?d99a8431' +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);

}
else
  audit(AUDIT_SUPPORTED, app, version);
