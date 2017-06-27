#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96046);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/12/21 21:58:44 $");

  script_name(english:"Symantec Endpoint Protection Small Business Edition Unsupported Version Detection");
  script_summary(english:"Checks the version of Symantec Endpoint Protection.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of Symantec Endpoint
Protection (SEP) Small Business Edition.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the installation of Symantec
Endpoint Protection (SEP) on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://support.symantec.com/en_US/article.DOC8217.html");
  script_set_attribute(attribute:"solution", value:
"Symantec Endpoint Protection (SEP) Small Business Edition has been
discontinued. Upgrade to Symantec Endpoint Protection Cloud.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("savce_installed.nasl");
  script_require_keys("Antivirus/SAVCE/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app = 'Symantec Endpoint Protection';
fix = null;

display_ver = get_kb_item_or_exit('Antivirus/SAVCE/version');
name        = get_kb_item('Antivirus/SAVCE/name');
edition     = get_kb_item('Antivirus/SAVCE/edition');
if (isnull(edition)) edition = '';

if (edition == 'sepsb')
{
  vuln = TRUE;
  app += ' Small Business Edition';
  fixed_ver = app + ' has reached end of life. Upgrade to Cloud.';

  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

register_unsupported_product(product_name:app, version:display_ver, cpe_base:"symantec:endpoint_protection");

  report =
    '\n  Product           : '+ app +
    '\n  Installed version : '+ display_ver +
    '\n  Fixed version     : '+ fixed_ver +
    '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, display_ver);
