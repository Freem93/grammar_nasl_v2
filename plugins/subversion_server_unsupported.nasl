#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78507);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/09/02 20:26:24 $");

  script_name(english:"Apache Subversion Server Unsupported Version Detection");
  script_summary(english:"Checks for an unsupported version of Apache Subversion Server.");

  script_set_attribute(attribute:"synopsis", value:
"A software revision control application installed on the remote host
is no longer supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Apache Subversion Server on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://subversion.apache.org/download/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Apache Subversion Server that is currently
supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:subversion");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("subversion_installed.nasl");
  script_require_keys("installed_sw/Subversion Server", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "Subversion Server";

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
path     = install['path'];
version  = install['version'];
provider = install['Packaged with'];

if (report_paranoia < 2) audit(AUDIT_PARANOID);

supported_versions = "1.8.x / 1.9.x";
support_cutoff = "1.8";

if (ver_compare(ver:version, fix:support_cutoff, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  register_unsupported_product(product_name:"Apache Subversion",
                               cpe_base:"apache:subversion", version:version);

  if (report_verbosity > 0)
  {
    report =
      '\n  Path               : ' + path +
      '\n  Packaged with      : ' + provider +
      '\n  Installed version  : ' + version +
      '\n  Supported versions : ' + supported_versions +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_NOT_INST, "An unsupported version of "+app);
