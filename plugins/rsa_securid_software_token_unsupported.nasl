#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57349);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/09/02 20:26:24 $");

  script_name(english:"RSA SecurID Software Token Unsupported Version Detection");
  script_summary(english:"Checks version of SecurID.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an unsupported version of RSA SecurID
Software Token.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of RSA SecurID Software
Token on the remote Windows host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # https://community.rsa.com/docs/DOC-40387#jive_content_id_RSA_SECURID_SOFTWARE_AUTHENTICATORS
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f415d5a7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of RSA SecurID Software Token that is currently
supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/20");

  script_set_attribute(attribute:"cpe", value:"cpe:/h:rsa:securid");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("rsa_securid_software_token_installed.nasl");
  script_require_keys("SMB/RSA SecurID Software Token/Version", "SMB/RSA SecurID Software Token/Path");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

version = get_kb_item_or_exit('SMB/RSA SecurID Software Token/Version');
path = get_kb_item_or_exit('SMB/RSA SecurID Software Token/Path');

# 4.1.2 is in extended support as per
# https://community.rsa.com/docs/DOC-40387#jive_content_id_RSA_SECURID_SOFTWARE_AUTHENTICATORS
fix = "4.1.2";
if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  register_unsupported_product(
    product_name:"RSA SecurID",
    cpe_base:"rsa:securid",
    version:version
  );

  port = get_kb_item('SMB/transport');
  if (!port)
    port = 445;

  order = make_list("Path", "Installed version", "Supported version");
  report = make_array(
    order[0], path,
    order[1], version,
    order[2], fix
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, "RSA SecurID Software Token", version, path);
