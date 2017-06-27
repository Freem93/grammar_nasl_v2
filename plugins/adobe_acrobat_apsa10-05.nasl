#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2010/11/17.  Use adobe_acrobat_apsb10-28.nasl (plugin ID 50613) instead.


include("compat.inc");


if (description)
{
  script_id(50380);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2012/06/14 20:15:06 $");

  script_cve_id("CVE-2010-3654");
  script_bugtraq_id(44504);
  script_osvdb_id(68932);

  script_name(english:"Adobe Acrobat 9 <= 9.4 (APSA10-05)");
  script_summary(english:"Checks version of Adobe Acrobat");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat on the remote Windows host is affected by
a code execution vulnerability."
  );
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains Adobe Acrobat version 9.4 or
earlier.  Such versions are affected by an unspecified memory
corruption vulnerability. 

A remote attacker could exploit this issue by getting a user to open a
maliciously crafted PDF containing SWF content, resulting in the
execution of arbitrary code.

This vulnerability is reportedly being exploited in the wild."
  );
  script_set_attribute(attribute:"see_also",value:"http://www.adobe.com/support/security/advisories/apsa10-05.html");
  script_set_attribute(attribute:"solution",value:
"Upgrade to the latest version when it is released.  Adobe states it
will be released the week of November 15, 2010.

In the meantime, deleting or renaming the version of 'authplay.dll'
that ships with Adobe Acrobat will result in a non-exploitable crash
when opening PDFs containing SWF content.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player "Button" Remote Code Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"vuln_publication_date",value:"2010/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/28");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");

  script_dependencies("adobe_acrobat_installed.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Acrobat/Version", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


# Deprecated
exit(0, "This plugin has been deprecated. Use adobe_acrobat_apsb10-28.nasl (plugin ID 50613) instead.");


include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");


version = get_kb_item_or_exit('SMB/Acrobat/Version');
path = get_kb_item_or_exit('SMB/Acrobat/Path');
version_ui = get_kb_item('SMB/Acrobat/Version_UI');

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# This only affects Acrobat 9.x <= 9.4
if (ver[0] != 9 || (ver[0] == 9 && ver[1] > 4))
  exit(0, 'Adobe Acrobat '+version_ui+' is installed not affected.');

# If we're looking at a vulnerable version, see if the workaround
# has been applied (delete/rename authplay.dll)
name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(1, "Failed to open a socket on port "+port+".");

session_init(socket:soc, hostname:name);
share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
dll = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\Acrobat\authplay.dll", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to "+share+" share.");
}

fh = CreateFile(
  file:dll,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

if (fh)
{
  vuln = TRUE;
  CloseFile(handle:fh);
}
else vuln = FALSE;
  
NetUseDel();

if (vuln)
{
  if (report_verbosity > 0)
  {
    dll_path = path + "\Acrobat\authplay.dll";
    report =
      '\n  Path              : '+path+
      '\n  Installed version : '+version_ui+
      '\n  Comment           : '+dll_path+' has not been deleted or renamed.\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, 'Adobe Acrobat '+version_ui+' is installed, but authplay.dll has been deleted or renamed so the host is not affected.');

