#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92840);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/09/02 20:26:24 $");

  script_name(english:"Symantec Mail Security for Microsoft Exchange Unsupported Version Detection");
  script_summary(english:"Checks the version of Symantec Mail Security for Microsoft Exchange.");

  script_set_attribute(attribute:"synopsis", value:
"A mail anti-virus application installed on the remote host is no
longer supported.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Symantec Mail Security for Microsoft Exchange on the remote host is no
longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # https://www.symantec.com/products/threat-protection/mail-security-exchange
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?495ddbd3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Symantec Mail Security for Microsoft Exchange
that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:mail_security");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("sms_for_msexchange.nasl");
  script_require_keys("Symantec_Mail_Security/Installed");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/SMS_Exchange/Installed");

app_name = "Symantec Mail Security for Microsoft Exchange";
install_path = get_kb_item_or_exit('SMB/SMS_Exchange/Path');
version = get_kb_item_or_exit('SMB/SMS_Exchange/Version');
supported_versions = "6.5.x / 7.0.x / 7.5.x";

eol_versions =
# SMSMSE 6.0.x branch is EOL
  make_array(
    "^6\.0\.", make_array(
      'eol_date', 'October 5 2012',
      'kb', 'https://support.symantec.com/en_US/article.ALERT1270.html'
      )
  );

port = get_kb_item('SMB/transport');
if (!port) port = 445;

foreach eol (keys(eol_versions))
{
  if (version =~ eol)
  {
    register_unsupported_product(product_name:"Symantec Mail Security for Microsoft Exchange",
                                 cpe_base:"symantec:mail_security", version:version);

    report =
      '\n  Path               : ' + install_path +
      '\n  Installed version  : ' + version +
      '\n  Supported versions : ' + supported_versions +
      '\n  EOL date           : ' + eol_versions[eol]['eol_date'] +
      '\n  EOL URL            : ' + eol_versions[eol]['kb'] +
      '\n';

    security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
    exit(0);
  }
}
audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, install_path);
