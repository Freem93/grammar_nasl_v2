#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(49284);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2011/04/20 01:55:04 $");

  script_cve_id("CVE-2010-2580");
  script_bugtraq_id(43182);
  script_osvdb_id(68045, 68046);

  script_name(english:"MailEnable SMTP Service Denial of Service Vulnerabilities (ME-10044)");
  script_summary(english:"Checks version of MailEnable / Installed Hotfixes");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote mail server is prone to denial of service attacks."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The SMTP service (MESMTPC.exe) included with the version of
MailEnable on the remote host reportedly does not properly check the
length of either the email address used in a 'MAIL FROM' command or
the domain name in a 'RCPT TO' command before using it in a log
message. 

A malicious attacker may be able to leverage these issues to trigger
an unhandled invalid parameter error and cause the affected SMTP
service to crash."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://secunia.com/secunia_research/2010-112/"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.mailenable.com/hotfix/"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.mailenable.com/Standard-ReleaseNotes.txt"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.mailenable.com/Professional-ReleaseNotes.txt"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.mailenable.com/Enterprise-ReleaseNotes.txt"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Either apply Hotfix ME-10044 or upgrade to MailEnable 4.26 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/20");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mailenable:mailenable");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

  script_dependencies("mailenable_detect.nasl", "smb_enum_services.nasl");
  script_require_keys("SMB/MailEnable/Installed");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


get_kb_item_or_exit("SMB/MailEnable/Installed");

if (get_kb_item("SMB/MailEnable/Standard")) prod = "Standard";
else if (get_kb_item("SMB/MailEnable/Professional")) prod = "Professional";
else if (get_kb_item("SMB/MailEnable/Enterprise")) prod = "Enterprise";
else exit(1, "Unknown MailEnable product variant.");

kb_base = "SMB/MailEnable/" + prod;
version = get_kb_item_or_exit(kb_base+"/Version");
hotfixes = get_kb_item(kb_base+"/Hotfixes");
path = get_kb_item(kb_base+"/Path");
if (isnull(path)) path = "n/a";


# Check for affected versions.
if (ver_compare(ver:version, fix:"4.26", strict:FALSE) == -1)
{
  # Exit if the hotfix is installed.
  if (hotfixes && "ME-10044" >< toupper(hotfixes))
    exit(0, "MailEnable "+prod+" Edition "+version+" is installed, and it includes the ME-10044 hotfix.");

  # Make sure the affected service is running, unless we're being paranoid.
  if (report_paranoia < 2)
  {
    services = get_kb_item("SMB/svcs");
    if (
      services && 
      "MESMTPC" >!< services &&
      "MailEnable SMTP" >!< services
    ) exit(0, "MailEnable "+prod+" Edition "+version+" is installed without the ME-10044 hotfix, but the SMTP service is not active.");
  }


  if (report_verbosity > 0)
  {
    if (isnull(hotfixes)) hotfixes = "none";

    report = 
      '\n  Product           : MailEnable ' + prod + ' Edition' +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Hotfixes          : ' + hotfixes +
      '\n  Fix               : ME-10044 / 4.26\n';
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
}
else exit(0, "MailEnable "+prod+" Edition "+version+" is installed and thus not affected.");
