#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70352);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/19 15:55:08 $");

  script_cve_id("CVE-2013-5327");
  script_bugtraq_id(62887);
  script_osvdb_id(98224);

  script_name(english:"Adobe RoboHelp 10 Unspecified Memory Corruption (APSB13-024)");
  script_summary(english:"Checks version of MDBMS.dll");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote host is affected by a memory corruption
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Adobe RoboHelp 10 install on the remote Windows host includes a
DLL (MDBMS.dll) that is earlier than 10.0.1.294. It is, therefore,
reportedly affected by an unspecified memory corruption vulnerability.
Successful exploitation of this issue could allow an attacker to
execute arbitrary code on the affected system.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb13-24.html");
  script_set_attribute(attribute:"solution", value:
"Update the MDBMS.dll file as discussed in Adobe Security Bulletin
APSB13-24.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:robohelp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("robohelp_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/Adobe_RoboHelp/Version");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");


get_kb_item_or_exit("SMB/Registry/Enumerated");


versions = get_kb_list("SMB/Adobe_RoboHelp/Version");
if (isnull(versions)) audit(AUDIT_NOT_INST, "Adobe RoboHelp");

port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

# Check the version of the DLL in each install.
dll = 'MDBMS.dll';
fixed_version = '10.0.1.294';

audits = make_array();
audits[0] = '';
audits[1] = '';

report = '';
foreach version (versions)
{
  path = get_kb_item("SMB/Adobe_RoboHelp/"+version+"/Path");
  if (isnull(path))
  {
    audits[1] += "Failed to identify the location of the Adobe RoboHelp "+version+" install." + '\n';
    continue;
  }
  path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);

  if (version !~ "^10\.")
  {
    audits[0] += "The Adobe RoboHelp install in '"+path+"' is "+version+", not 10.x." + '\n';
    continue;
  }

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel(close:FALSE);
    audits[1] += "Failed to connect to the '"+share+"' share." + '\n';
    continue;
  }

  file = path + "\RoboHTML\" + dll;
  fh = CreateFile(
    file:ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:file),
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh))
  {
    NetUseDel(close:FALSE);
    audits[0] += "The Adobe RoboHelp "+version+" install in '"+path+"' does not have a copy of '"+dll+"'." + '\n';
    continue;
  }

  fver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
  NetUseDel(close:FALSE);

  if (isnull(fver))
  {
    audits[1] += "Failed to extract the version of '"+dll+"' included with the Adobe RoboHelp "+version+" install in '"+path+"'." + '\n';
    continue;
  }

  fversion = join(fver, sep:".");
  if (ver_compare(ver:fver, fix:fixed_version) < 0)
  {
    report += '\n  File              : ' + file +
              '\n  Installed version : ' + fversion +
              '\n  Fixed version     : ' + fixed_version +
              '\n';
  }
  else
  {
    audits[0] += "The Adobe RoboHelp "+version+" install in '"+path+"' includes version "+fversion+" of '"+dll+"' and thus is not affected." + '\n';
    continue;
  }
}


if (strlen(report))
{
  if (report_verbosity > 0)
  {
    if (strlen(audits[1]))
    {
      report +=
        '\n' + 'Note that the results may be incomplete because of the following' +
        '\n' + 'error(s) encountered :' +
        '\n' +
        audits[1];
    }

    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  if (strlen(audits[1])) exit(1, "The results may be incomplete because of one or more errors.");
  else exit(0);
}
else
{
  if (strlen(audits[1])) exit(1, audits[1]);
  else if (strlen(audits[0])) exit(0, audits[0]);
  else audit(AUDIT_HOST_NOT, "affected");
}
