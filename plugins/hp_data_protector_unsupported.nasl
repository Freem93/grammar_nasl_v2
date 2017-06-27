#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64475);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/08/22 20:52:04 $");

  script_name(english:"HP Data Protector Unsupported");
  script_summary(english:"Checks the version of HP Data Protector.");

  script_set_attribute(attribute:"synopsis", value:
"An unsupported version of a backup service is running on the remote
host.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
HP Data Protector on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # https://softwaresupport.hp.com/web/softwaresupport/obsolescence-migrations
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f214fd3");
  # https://web.archive.org/web/20130716104515/http://support.openview.hp.com/encore/dp_5.0_5.1_5.5_mediaops_3.0_5.5.jsp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3c5cd32d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of HP Data Protector that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:storage_data_protector");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:data_protector");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_data_protector_installed.nasl","hp_data_protector_installed_local.nasl");
  script_require_keys("Services/data_protector/version");
  script_require_ports("Services/hp_openview_dataprotector", 5555);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:'hp_openview_dataprotector', default:5555, exit_on_fail:TRUE);

version = get_kb_item_or_exit("Services/data_protector/version");
if (version == "unknown") audit(AUDIT_UNKNOWN_APP_VER, "HP Data Protector");
# Versions earlier than A.06.10 are unsupported
ver = split(version, sep:'.', keep:FALSE);

if (ver[0] == 'A')
{
  for (i = 1; i < max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (ver[1] < 8 || (ver[1] == 8 && ver[2] < 10))
  {
    register_unsupported_product(product_name:'HP Data Protector',
                                 version:version, cpe_base:"hp:storage_data_protector");
    report =
      '\n  Installed version  : ' + version +
      '\n  Supported versions : 8.1x / 9.0x' +
      '\n  EOL URL            : https://softwaresupport.hp.com/web/softwaresupport/obsolescence-migrations\n';
    security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
  }
  else
    audit(AUDIT_LISTEN_NOT_VULN, 'HP Data Protector', port, version);
}
else audit(AUDIT_VER_FORMAT, version);
