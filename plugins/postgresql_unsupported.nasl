#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63347);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/07 18:08:56 $");

  script_name(english:"PostgreSQL Unsupported Version Detection");
  script_summary(english:"Checks the version of PostgreSQL.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an unsupported version of a database
server.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
PostgreSQL on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/support/versioning/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of PostgreSQL that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("postgresql_version.nbin");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/postgresql", 5432);

  exit(0);
}

include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"postgresql", default:5432, exit_on_fail:TRUE);

version = get_kb_item_or_exit('database/'+port+'/postgresql/version');
source = get_kb_item_or_exit('database/'+port+'/postgresql/source');

# Check for backported services
get_backport_banner(banner:source);
if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = split(version, sep:'.');
for (i=0; i < max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ( ver[0] < 9 ) ||
  ( ver[0] == 9 && ver[1] <= 1)
)
{
  register_unsupported_product(product_name:"PostgreSQL",
                               cpe_base:"postgresql:postgresql", version:version);

  if (report_verbosity > 0)
  {
    report +=
      '\n  Version source     : ' + source +
      '\n  Installed version  : ' + version +
      '\n  Supported versions : 9.2 / 9.3 / 9.4 / 9.5 / 9.6\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'PostgreSQL', port, version);
