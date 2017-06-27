#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(49270);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_name(english:"Stuxnet Worm Detection");
  script_summary(english:"Looks for files indicative of the Stuxnet worm");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host has been infected with the Stuxnet worm.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has files present on the system that indicate
the Stuxnet worm has infected the system. This worm attempts to spread
in several ways, making use of known Windows vulnerabilities and
removable media. It has been seen making use of several 0-day
vulnerabilities as well as attacking Siemens SCADA systems.

This plugin looks for files present on Windows systems that are
generated upon infection. The Stuxnet executable uses hard-coded file
names, and generates several files, such as malicious drivers that are
loaded by the system. The presence of these files is indicative of a
system that has been infected through one of the multiple vectors
Stuxnet attempts to use.");
  # http://www.symantec.com/security_response/writeup.jsp?docid=2010-071400-3123-99
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c2e869c");
  # http://www.symantec.com/connect/de/blogs/stuxnet-introduces-first-known-rootkit-scada-devices
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0c7c344d"
  );
  script_set_attribute(attribute:"solution", value:
"Update the host's antivirus software, clean the host, and scan again
to ensure its removal. If symptoms persist, re-installation of the
infected host is recommended.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Backdoors");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

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
stuxfiles = make_list("inf\mdmcpq3.PNF", "inf\mdmeric3.PNF", "inf\oem6C.PNF", "inf\oem7A.PNF", "system32\drivers\mrxcls.sys", "system32\drivers\mrxnet.sys", "system32\s7otbxsx.dll");

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to "+share+" share.");
}


# Check for the Stuxnet files
foreach file (stuxfiles) {
  filename = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\"+file, string:path);
  fh = CreateFile(
    file:filename,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (!isnull(fh))
  {
    report += '\n  ' + path + '\\'+file;
    CloseFile(handle:fh);

    # If one file is found, consider infected and break
    if (!thorough_tests) break;
  }
}

NetUseDel();

# Issue a report if the main binary is detected, and supporting files are present on the system.
if (report)
{
  if (max_index(split(report)) > 1) s = "s";
  else s = "";

  report = '\nNessus found the following Stuxnet file'+s+' : '+
           '\n'+report+'\n';

  if (!thorough_tests)
  {
    report += '\n' +
"Note that Nessus stopped looking for Stuxnet-related files after
detecting the one listed above. To detect all Stuxnet related files,
enable the 'Perform thorough tests' setting and re-scan."+'\n';
  }

  if (report_verbosity > 0) security_hole(port:port, extra:report);
  else security_hole(port);

  exit(0);
}
else exit(0, "The Stuxnet worm was not found.");
