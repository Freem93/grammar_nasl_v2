#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76314);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/04/05 19:55:08 $");

  script_name(english:"Samba Unsupported Version Detection");
  script_summary(english:"Checks the version of Samba.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of Samba.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Samba on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://wiki.samba.org/index.php/Samba_Release_Planning");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Samba that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

lanman = get_kb_item_or_exit("SMB/NativeLanManager");
if ("Samba " >!< lanman) audit(AUDIT_NOT_LISTEN, "Samba", port);
version = lanman - 'Samba ';

if (report_paranoia < 2) audit(AUDIT_PARANOID);

eol_date = NULL;
eol_url  = "https://wiki.samba.org/index.php/Samba_Release_Planning";
supported_versions = "4.4.x / 4.5.x / 4.6.x / 4.7.x";
eol_dates = make_array(
  "^4\.3($|[^0-9])"    , "2017-03-07",
  "^4\.2($|[^0-9])"    , "2016-09-07",
  "^4\.1($|[^0-9])"    , "2016-03-22",
  "^4\.0($|[^0-9])"    , "2015/09/08",
  "^3\.6($|[^0-9])"    , "2015/03/04",
  "^3\.5($|[^0-9])"    , "2013/10/11",
  "^3\.4($|[^0-9])"    , "2012/12/11",
  "^3\.3($|[^0-9])"    , "2011/08/09",
  "^3\.2($|[^0-9])"    , "2010/03/01",
  "^3\.[01]($|[^0-9])" , "2009/08/05",
  "^[0-2]\."           , "2009/08/05"
);

foreach regex (keys(eol_dates))
{
  if (version !~ regex) continue;
  eol_date = eol_dates[regex];
  break;
}

if (!isnull(eol_date))
{
  register_unsupported_product(product_name:"Samba",
                               cpe_base:"samba:samba", version:version);

  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version  +
             '\n  EOL date          : ' + eol_date +
             '\n  EOL URL           : ' + eol_url  +
             '\n  Supported version : ' + supported_versions +
             '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Samba", port, version);
