#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92757);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/09/02 20:26:24 $");

  script_name(english:"Symantec Mail Security for Domino Unsupported");
  script_summary(english:"Checks for Symantec Mail Security for Domino.");

  script_set_attribute(attribute:"synopsis", value:
"A mail security application installed on the remote host is
unsupported.");
  script_set_attribute(attribute:"description", value:
"The installation of Symantec Mail Security for Domino on the remote
host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://support.symantec.com/en_US/article.ALERT2023.html");
  script_set_attribute(attribute:"solution", value:
"Remove Symantec Mail Security for Domino from the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:mail_security_for_domino");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("sms_for_domino.nasl");
  script_require_keys("Symantec_Mail_Security/Installed");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/SMS_Domino/Installed");

path = get_kb_item_or_exit('SMB/SMS_Domino/Path');
version = get_kb_item_or_exit('SMB/SMS_Domino/Version');

register_unsupported_product(product_name:"Symantec Mail Security for Domino",
                               cpe_base:"symantec:mail_security", version:version);

port = get_kb_item('SMB/transport');
if (!port) port = 445;

report =
  '\n  Path              : ' + path +
  '\n  Installed version : ' + version +
  '\n  EOL URL           : https://support.symantec.com/en_US/article.ALERT2023.html\n';

security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
