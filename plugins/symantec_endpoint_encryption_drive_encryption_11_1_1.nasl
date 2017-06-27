#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91124);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/08/16 14:42:21 $");

  script_cve_id("CVE-2015-8156");
  script_bugtraq_id(90050);
  script_osvdb_id(138214);
  script_xref(name:"IAVB", value:"2016-B-0090");

  script_name(english:"Symantec Endpoint Encryption 11.x < 11.1.1 Unquoted Search Path Local Privilege Escalation (SYM16-006)");
  script_summary(english:"Checks the version of Symantec Endpoint Encryption Drive Encryption.");

  script_set_attribute(attribute:"synopsis", value:
"A drive encryption management agent installed on the remote Windows
host is affected by a local privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Symantec Endpoint Encryption (SEE) Drive Encryption
Client installed on the remote Windows host is 11.x prior to 11.1.1.
It is, therefore, affected by a privilege escalation vulnerability due
to an unquoted search path in EEDService. A local attacker can exploit
this to escalate privileges.");
  # https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20160506_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?353a6a04");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Endpoint Encryption version 11.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_encryption");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_endpoint_encryption_drive_encryption_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Symantec Endpoint Encryption Drive Encryption Client");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_name = "Symantec Endpoint Encryption Drive Encryption Client";
fix = "11.1.1.0";
install = get_single_install(app_name:app_name);

version = install['version'];
path    = install['path'];

# 11.x < 11.1.1
if ((version !~ "^11(\.|$)") || (ver_compare(ver:version, fix:fix, strict:FALSE) < 0))
{
  port = get_kb_item("SMB/transport");
  if (empty_or_null(port))
    port = 445;

  report = report_items_str(
    report_items:make_array(
      "Path", path,
      "Installed version", version,
      "Fixed version", fix
    ),
    ordered_fields:make_list("Path", "Installed version", "Fixed version")
  );
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
