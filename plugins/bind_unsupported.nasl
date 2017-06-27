#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86072);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/08 15:47:27 $");

  script_name(english:"ISC BIND Unsupported Version Detection");
  script_summary(english:"Checks for unsupported versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an unsupported version of ISC BIND.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
ISC BIND running on the remote name server is 9.8.x or earlier. It is,
therefore, no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of ISC BIND that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
ver = get_kb_item_or_exit("bind/version");
if (report_paranoia < 2) audit(AUDIT_PARANOID); # patch can be applied
fix = '';
# 9.8.x and earlier are vulnerable
if (
  ver =~ "^(9$|9\.[0-8]([^0-9]|$))" ||
  ver =~ "^(8$|8\.[0-9]([^0-9]|$))" ||
  ver =~ "^(4$|4\.[0-9]([^0-9]|$))" 
) fix = '9.9.8 or higher';

if (!empty_or_null(fix))
{
  register_unsupported_product(product_name:"ISC Bind", version:ver, cpe_base:"isc:bind");
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n  End of Support URL: https://www.isc.org/downloads/' + 
      '\n' ;
    security_hole(port:53, proto:"udp", extra:report);
  }
  else security_hole(port:53, proto:"udp");
}
else audit(AUDIT_LISTEN_NOT_VULN, "BIND", 53, ver, "UDP");
