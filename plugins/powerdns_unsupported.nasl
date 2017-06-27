#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87953);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/01/15 15:43:45 $");

  script_name(english:"PowerDNS Unsupported Version Detection");
  script_summary(english:"Checks for unsupported versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an unsupported version of PowerDNS.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
PowerDNS running on the remote name server is 2.x or earlier. It is,
therefore, no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://doc.powerdns.com/md/end-of-life/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of PowerDNS that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:powerdns:powerdns");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("pdns_version.nasl");
  script_require_keys("pdns/version_full", "pdns/version_source", "Settings/ParanoidReport");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit("pdns/version_full");
ver_source = get_kb_item_or_exit("pdns/version_source");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app  = "PowerDNS";
port = 53;

# All versions prior to 3.x are unsupported
if (ver !~ "^[012]\.")
  audit(AUDIT_LISTEN_NOT_VULN, app, port, ver, "UDP");

supported_vers = '3.x / 4.x';

register_unsupported_product(product_name:app, version:ver, cpe_base:"powerdns:powerdns");

if (report_verbosity > 0)
{
  url = "https://doc.powerdns.com/md/end-of-life/";

  report =
    '\n  Version source     : ' + ver_source +
    '\n  Installed version  : ' + ver +
    '\n  Supported versions : ' + supported_vers +
    '\n  EOL URL            : ' + url + 
    '\n' ;
  security_hole(port:port, proto:"udp", extra:report);
}
else security_hole(port:port, proto:"udp");
