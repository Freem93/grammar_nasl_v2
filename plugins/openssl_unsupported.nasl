#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78555);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/12 19:08:55 $");

  script_name(english:"OpenSSL Unsupported");
  script_summary(english:"Performs a banner check.");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported service is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote web server is running a version of
OpenSSL that is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/policies/releasestrat.html");
  # https://mta.openssl.org/pipermail/openssl-announce/2014-December/000000.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4d55548d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of OpenSSL that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

service_name = "OpenSSL";
latest_supported_versions = "1.1.0 / 1.0.2";
lowest_supported_branch  = "1.0.2";

# Make sure OpenSSL is installed.
port = get_kb_item_or_exit("openssl/port");

# Get relevant data for installed version.
kb_base = "openssl/" + port + "/";
version = get_kb_item_or_exit(kb_base + "pristine_version");
backported = get_kb_item(kb_base + "backported");
if (empty_or_null(backported)) backported = 0;

# If the banner is backported, and we're not running a paranoid
# scan, audit out.
if (backported && report_paranoia < 2) audit(AUDIT_BACKPORT_SERVICE, port, service_name);

# For unsupported check, just want to use the numeric portion for
# branch check
matches = eregmatch(pattern:"^([\d.]+)", string:version);
if (empty_or_null(matches)) audit(AUDIT_SERVICE_VER_FAIL, service_name, port);
numeric_version = matches[1];

if (ver_compare(ver:numeric_version, fix:lowest_supported_branch, strict:FALSE) == -1)
{
  register_unsupported_product(product_name:"OpenSSL",
                               cpe_base:"openssl:openssl", version:version);
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version  : ' + version +
      '\n  Supported versions : ' + latest_supported_versions +
      '\n  EOL URL            : https://www.openssl.org/policies/releasestrat.html' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port:port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, service_name, port, version);
