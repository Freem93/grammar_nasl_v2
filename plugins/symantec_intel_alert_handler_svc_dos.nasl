#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51190);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/03 20:40:06 $");

  script_cve_id("CVE-2010-3268");
  script_bugtraq_id(45368);
  script_osvdb_id(70002);
  script_xref(name:"Secunia", value:"42593");

  script_name(english:"Symantec Products Intel Alert Handler Remote DoS");
  script_summary(english:"Checks version number of Symantec Antivirus/SEP");

  script_set_attribute(attribute:"synopsis",
    value:
"The remote Windows host has a service that is affected by a denial of
service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Intel Alert Handler Service (hndlrsvc.exe) included with Alert
Management System 2 (AMS2), an optional component included with either
Symantec Antivirus Corporate Edition or Symantec Endpoint Protection
version prior to 11.x, is installed on the remote host.  The installed 
service reportedly fails to correctly handle 'CommandLine' field in an 
AMS request, and could be exploited by a remote attacker to crash the 
affected service.");

   # http://www.coresecurity.com/content/symantec-intel-handler-service-remote-dos
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?e058ea4d");
  script_set_attribute(attribute:"see_also",value:"http://seclists.org/fulldisclosure/2010/Dec/261");
  script_set_attribute(attribute:"solution",value:
"Either upgrade to version 11.x since it does not use Intel AMS code
or disable Intel AMS.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"vuln_publication_date",value:"2010/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/13");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:endpoint_protection");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:intel:intel_alert_management_system");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("savce_installed.nasl", "smb_enum_services.nasl");
  script_require_keys("Antivirus/SAVCE/version", "SMB/svc/Intel Alert Handler");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_header.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Antivirus/SAVCE/version");

status = get_kb_item_or_exit("SMB/svc/Intel Alert Handler");
if (status != SERVICE_ACTIVE && report_paranoia < 2 )
    exit(0, "The Intel Alert Handler service is installed but not active.");

if (ver_compare(ver:version, fix:'11.0',strict:FALSE) == -1)
{
 if (report_verbosity > 0)
 {
   report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 11.x\n';
   security_warning(port:get_kb_item("SMB/transport"),extra:report);
 }
 else security_warning(get_kb_item("SMB/transport"));
 exit(0);
}
else exit(0,"Version "+ version + " is installed, and is not known to be affected.");
