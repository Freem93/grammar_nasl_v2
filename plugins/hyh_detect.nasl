#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(49211);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_name(english:"Here You Have Email Worm Detection");
  script_summary(english:"Looks for files indicative of the Here You Have email worm");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has been infected with the Here You Have email
worm.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has files present on the system that indicate
that the 'Here You Have' email worm is present. A user of this host
likely received an email containing a malicious '.scr' (screen saver)
file and infected the host as a result of running this file.

This malware has several features. The most damaging is to
self-propagate and infect systems via email, removable drives, shared
folders and instant messaging. The worm sends copies of itself to
addresses found in Microsoft Outlook address books and Yahoo!
Messenger, enticing the user to click on the attached '.scr' file,
which leads to further propagation of the worm.

The malware also disables a variety of antivirus packages from a
multitude of vendors, turning them off in order to ensure its survival
on a newly infected system. These AV packages remain disabled while
the system is infected, so an AV scan may not detect an actual
infection.

The malware also attempts to recover saved passwords for things such
as sites stored in Internet Explorer and Firefox, wireless network
keys, and more. This stolen data is then returned to the attacker. It
does this by using third-party, non-malicious tools designed for
credential recovery. The way these tools are stored and used by this
malware is non-standard, however, and are an indication of infection
by this malware.");
  # http://www.symantec.com/security_response/writeup.jsp?docid=2010-090922-4703-99
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0537683e"
  );
  # https://web.archive.org/web/20131210115341/http://isc.sans.edu:80/diary/%27Here+You+Have%27+Email+/9529
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7378f54d"
  );
  script_set_attribute(attribute:"solution", value:
"Update the host's antivirus software, clean the host and scan again to
ensure its removal. If symptoms persist, re-installation of the
infected host is recommended.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"malware", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Backdoors");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0, "The 'SMB/Registry/Enumerated' KB item is missing.");

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');


path = hotfix_get_systemroot();
if (!path) exit(1, "Can't get system root.");

report = "";

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
hyhexe = "csrss.exe";
hyhupdate = "updates.exe";

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to "+share+" share.");
}

# Check for the main HYH executable
filename = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\"+hyhexe, string:path);
fh = CreateFile(
  file:filename,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

if (!isnull(fh))
{
  report += '\n' +
    'Nessus found the Here You Have executable installed at : ' + path + '\\'+hyhexe;
  CloseFile(handle:fh);
}

# Check for malicious HYH backup file for plugin accuracy.
if (!report || report_paranoia < 2)
{
  filename = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\system\"+hyhupdate, string:path);

  fh = CreateFile(
      file:filename,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
  );

  if (!isnull(fh))
  {
      report += '\n' +
      'Nessus found a malicious Here You Have file at : ' + path + '\\'+hyhupdate;
      CloseFile(handle:fh);
  }
}

NetUseDel();

# Issue a report if the main binary is detected, and supporting files are present on the system.
if (report)
{
  if (report_verbosity > 0) security_hole(port:port, extra:report);
  else security_hole(port);

  exit(0);
}
else exit(0, "The Here You Have email worm was not found.");
