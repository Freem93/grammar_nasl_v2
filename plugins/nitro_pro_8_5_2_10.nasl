#
# (C) Tenable network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66026);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/10/27 15:03:55 $");

  script_cve_id("CVE-2013-2773");
  script_bugtraq_id(58928);
  script_osvdb_id(92118);

  script_name(english:"Nitro Pro Insecure Library Loading");
  script_summary(english:"Checks version of Nitro Pro");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a PDF toolkit installed that is affected by an
insecure library loading vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Nitro Pro installed on the remote Windows host is
earlier than 8.5.2.10 and is, therefore, reportedly affected by an
insecure library loading vulnerability.  By tricking a user into opening
a specially crafted file, an attacker could execute arbitrary code on
the remote host subject to the privileges of the user running the
affected application.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2013/Apr/60");
  script_set_attribute(attribute:"solution", value:"Upgrade to Nitro Pro 8.5.2.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nitro:nitro_pdf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("nitro_pro_installed.nasl");
  script_require_keys("SMB/Nitro Pro/installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

info = '';
info2 = '';
vuln = 0;
installs = get_kb_list("SMB/Nitro Pro/*/Path");
if (isnull(installs)) audit(AUDIT_KB_MISSING, 'SMB/Nitro Pro/*/Path');

vuln = 0;
foreach install (keys(installs))
{
  path = installs[install];
  version = install - 'SMB/Nitro Pro/' - '/Path';

  if (ver_compare(ver:version, fix:'8.5.2.10', strict:FALSE) < 0)
  {
    info +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.5.2.10\n';
    vuln++;
  }
  else
    info2 += ' and ' + version;
}

if (vuln)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    if (vuln > 1) s = "s of Nitro Pro are";
    else s = " of Nitro Pro is";

    report =
      '\nThe following vulnerable instance' + s + ' installed on the' +
      '\nremote host :\n'+
      info;
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}

if (info2)
{
  info2 -= ' and ';
  if (' and ' >< info2) be = 'are';
  else be = 'is';

  exit(0, 'The host is not affected since Nitro Pro '+info2+' '+be+' installed.');
}
else exit(1, 'Unexpected error -  \'info2\' is empty.');
