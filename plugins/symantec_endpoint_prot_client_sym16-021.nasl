#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96045);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/22 20:42:29 $");

  script_cve_id("CVE-2016-5311");
  script_bugtraq_id(94295);
  script_osvdb_id(147489);

  script_name(english:"Symantec Endpoint Protection Client < 22.8.0.50 Elevation of Privilege (SYM16-021)");
  script_summary(english:"Checks the SEP Client version.");

  script_set_attribute(attribute:"synopsis", value:
"A security application installed on the remote host is affected by an
elevation of privilege vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Endpoint Protection (SEP) Client installed on
the remote Windows host is prior to 22.8.0.50. It is, therefore,
affected by an elevation of privilege vulnerability due to improper
path restrictions when loading DLL files. A local attacker can exploit
this, by placing a specially crafted DLL file in the installation path
or DLL search path, to inject and execute arbitrary code.");
  # https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20161117_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c0802a8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Endpoint Protection (SEP) version 22.8.0.50 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

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

vuln = FALSE;
fixed_ver = '22.8.0.50';

# Symantec Endpoint Protection Cloud
if (name == 'Endpoint Protection.cloud')
{
  app += ' Small Business Edition Cloud';
  if (ver_compare(ver:display_ver, fix:fixed_ver, strict:FALSE) == -1)
  {
    port = get_kb_item("SMB/transport");
    if (!port) port = 445;

    report =
      '\n  Product           : '+ app +
      '\n  Installed version : '+ display_ver +
      '\n  Fixed version     : '+ fixed_ver +
      '\n';
    security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
  }
}
else audit(AUDIT_INST_VER_NOT_VULN, app, display_ver);
