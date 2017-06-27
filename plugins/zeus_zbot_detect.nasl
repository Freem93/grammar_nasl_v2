#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(45085);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/21 20:34:21 $");

  script_name(english:"Zeus/Zbot Banking Trojan/Data Theft (credentialed check)");
  script_summary(english:"Looks for files indicative of the Zeus/Zbot trojan");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host has been infected with the Zeus/Zbot trojan.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has files that indicate that the Zeus (also
known as Zbot) banking trojan has been installed, or that stolen data
collected by this trojan remains on the system.

The Zeus trojan will intercept and log activity related to online
banking, as well as other logins, such as web, ftp, email, etc, and
report these credentials to a third party. The targeted credentials
are unique per Zeus infection, so any website can be affected.

Zeus also gives the attacker complete control over the system,
allowing for further malware to be installed, the ability to proxy
traffic through an infected host, and other things like the ability to
kill the system.

False positives may occur if file names identical to files Zeus
creates are detected on the system. These file names mimic standard
Windows files, and should be considered suspicious under any
circumstances.");
  script_set_attribute(attribute:"see_also", value:"https://zeustracker.abuse.ch/faq.php");
  script_set_attribute(
    attribute:"see_also",
    value:"http://news.cnet.com/8301-27080_3-10455525-245.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://en.wikipedia.org/wiki/Zeus_%28trojan_horse%29"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.secureworks.com/research/threats/zeus/?threat=zeus"
  );
  script_set_attribute(attribute:"solution", value:
"Update the host's antivirus software, clean the host, and scan again
to ensure its removal. If symptoms persist, re-installation of the
infected host is recommended.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"malware", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Backdoors");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("audit.inc");
include("smb_hotfixes.inc");


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
zeusexe = make_list("sdra64.exe","ntos.exe","oembios.exe","twext.exe");
zeusdata = make_list("wnspoem\audio.dll","sysproc64\sysproc86.sys","twain_32\local.ds","lowsec\local.ds");

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to "+share+" share.");
}

# Check for installed Zeus executables.
foreach file (zeusexe)
{
  filename = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\system32\"+file, string:path);

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
	  'Nessus found Zeus installed at : ' + path + '\\system32\\'+file;

    CloseFile(handle:fh);

    if (!thorough_tests) break;
  }
}


# Check for stolen data log.
foreach file (zeusdata)
{
  filename = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\system32\"+file, string:path);

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
	  'Nessus found stolen data at : ' + path + '\\system32\\'+file;

    CloseFile(handle:fh);

    if (!thorough_tests) break;
  }
}

NetUseDel();

# Issue a report if necessary.
if (report)
{
  if (report_verbosity > 0)
  {
    report +=
      '\n' + 'Note that reported directories and/or files are likely to have the' +
      '\n' + '\'HIDDEN\' attribute set to conceal them from casual inspection.\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}
else exit(0, "The trojan was not found.");
