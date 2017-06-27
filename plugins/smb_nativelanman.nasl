#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10785);
 script_version("$Revision: 1.49 $");
 script_cvs_date("$Date: 2017/02/21 18:16:30 $");

 script_name(english:"Microsoft Windows SMB NativeLanManager Remote System Information Disclosure");
 script_summary(english:"Extracts the remote native LAN manager name.");

 script_set_attribute(attribute:"synopsis", value:
"It was possible to obtain information about the remote operating
system.");
 script_set_attribute(attribute:"description", value:
"Nessus was able to obtain the remote operating system name and version
(Windows and/or Samba) by sending an authentication request to port
139 or 445. Note that this plugin requires SMB1 to be enabled on the
host.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2001/10/17");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2017 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("netbios_name_get.nasl", "samba_detect.nasl");
 script_require_ports(139,445, "/tmp/settings");
 exit(0);
}

include("audit.inc");
include("smb_func.inc");

port = kb_smb_transport();

if (!smb_session_init(smb2:FALSE)) audit(AUDIT_FN_FAIL, 'smb_session_init');

r = NetUseAdd(share:"IPC$");
if (r == 1)
  NetUseDel();

if (!isnull(Session[17]))
{
  set_kb_item(name:"SMB/SMBv1_is_supported", value:TRUE);
  report = 'The remote Operating System is : ' + Session[17];
  if (!isnull(Session[18]))
    report += '\nThe remote native LAN manager is : ' + Session[18];
  if (!isnull(Session[19]))
    report += '\nThe remote SMB Domain Name is : ' + Session[19];

  report += '\n';

  if (!get_kb_item("SMB/workgroup") && Session[19] )
  {
   set_kb_item (name:"SMB/workgroup", value:Session[19]);
  }

  if ( Session[18] )
  {
   set_kb_item(name:"SMB/NativeLanManager", value:Session[18]);

   if (
    "Samba" >< Session[18] ||
    Session[18] == "NT1" ||
    "Isilon OneFS" >< Session[18] ||
    "Netreon LANMAN" >< Session[18]
   ) replace_kb_item(name:"SMB/not_windows", value:TRUE);
  }

  os = Session[17];

  if ("Windows NT" >< os)
    os = "Windows 4.0";
  else if ("Windows XP" >< os)
    os = "Windows 5.1";
  else if ("Windows Server 2003" >< os)
    os = "Windows 5.2";
  else if ("Vista" >< os)
    os = "Windows 6.0";
  else if (
    ("Windows Server 2008" >< os || "Windows Server (R) 2008" >< os)
    && "R2" >!< os
  )
    os = "Windows 6.0";
  else if ("Windows 7" >< os)
    os = "Windows 6.1";
  else if (
    ("Windows Server 2008" >< os || "Windows Server (R) 2008" >< os)
    && "R2" >< os
  )
    os = "Windows 6.1";
  else if ("Windows 8" >< os && "8.1" >!< os)
    os = "Windows 6.2";
  else if ("Windows Server 2012" >< os && "R2" >!< os)
    os = "Windows 6.2";
  else if ("Windows 8.1" >< os)
    os = "Windows 6.3";
  else if ("Windows Server 2012" >< os && "R2" >< os)
    os = "Windows 6.3";
  else if ("Windows 10" >< os && "Insider Preview" >< os)
    os = "Windows 6.3";
  else if ("Windows 10" >< os && "Insider Preview" >!< os)
    os = "Windows 10.0";

 if ( os )
 {
  set_kb_item(name:"Host/OS/smb", value:os);
  set_kb_item(name:"Host/OS/smb/Confidence", value:70);
  set_kb_item(name:"Host/OS/smb/Type", value:"general-purpose");

  if (
    "SpinStream2" >< os ||
    "EMC-SNAS" >< os ||
    "unix" >< tolower(os) ||
    "linux" >< tolower(os)
  ) replace_kb_item(name:"SMB/not_windows", value:TRUE);
 }

 security_note(port:port, extra:report);
}

if (isnull(report))
{
  set_kb_item(name:"SMB/SMBv1_is_supported", value:FALSE);
  exit(0, "Host does not allow SMB1.");
}
