#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74039);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/08 16:36:54 $");

  script_name(english:"ClamAV Unsupported Version Detection");
  script_summary(english:"Checks response to a clamd VERSION command.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of ClamAV.");
  script_set_attribute(attribute:"description", value:
"According to its version, the ClamAV clamd antivirus daemon running on
the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vrtadmin/clamav-faq/blob/master/faq/faq-eol.md");
  script_set_attribute(attribute:"see_also", value:"http://www.clamav.net/doc/eol.html");
  script_set_attribute(attribute:"see_also", value:"http://www.clamav.net/download.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of ClamAV that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:clamav:clamav");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("clamav_detect.nasl");
  script_require_keys("Antivirus/ClamAV/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Antivirus/ClamAV/version");
port = get_service(svc:"clamd", default:3310, exit_on_fail:TRUE);

# nb: banner checks of open source software are prone to false-
# positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Check the version number.
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Clam AV only does security patching on the latest minor release.
if (ver[0] == 0 && ver[1] < 98 && ver[2] < 7)
{

  register_unsupported_product(product_name:"ClamAV",
                               version:version, cpe_base:"clamav:clamav");

  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Supported version : 0.98.7 or later \n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The ClamAV " + version + " installation on port " + port + " is still supported.");
