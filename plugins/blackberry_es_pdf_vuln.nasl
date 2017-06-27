#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33550);
  script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2015/01/12 17:12:43 $");

  script_cve_id("CVE-2008-3246");
  script_bugtraq_id(30188);
  script_osvdb_id(47296);
  script_xref(name:"Secunia", value:"31092");
  script_xref(name:"Secunia", value:"31141");

  script_name(english:"BlackBerry Multiple Products PDF Distiller Component PDF Processing Arbitrary Code Execution");
  script_summary(english:"Checks version and looks for workaround");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a code
execution vulnerability");
 script_set_attribute(attribute:"description", value:
"The version of BlackBerry Enterprise Server / BlackBerry Unite! on the
remote host reportedly contains a vulnerability in the PDF distiller
component of the BlackBerry Attachment Service. A remote attacker may
be able to leverage this issue to execute arbitrary code on the
affected host subject to the privileges under which the application
runs, generally 'Administrator', by sending an email message with a
specially crafted PDF file and having that opened for viewing on a
BlackBerry smartphone.");
 script_set_attribute(attribute:"see_also", value:"http://www.blackberry.com/btsc/viewContent.do?externalId=KB15766");
 script_set_attribute(attribute:"see_also", value:"http://www.blackberry.com/btsc/viewContent.do?externalId=KB15770" );
 script_set_attribute(attribute:"solution", value:
"If using BlackBerry Enterprise Server, either upgrade to version 4.1
Service Pack 6 (4.1.6), apply an appropriate interim security software
update, or prevent the Attachment Service from processing PDF files.

If using BlackBerry Unite!, either upgrade to 1.0 Service Pack 1
(1.0.1) bundle 36 or later or prevent the Attachment Service from
processing PDF files.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(94);

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/21");

script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rim:blackberry_enterprise_server");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("blackberry_es_installed.nasl", "smb_hotfixes.nasl");
  script_require_keys("BlackBerry_ES/Product", "BlackBerry_ES/Version", "BlackBerry_ES/AttachmentServer", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");
include("audit.inc");

prod = get_kb_item_or_exit("BlackBerry_ES/Product");
version = get_kb_item_or_exit("BlackBerry_ES/Version");
path = get_kb_item_or_exit("BlackBerry_ES/Path");
get_kb_item_or_exit("SMB/Registry/Enumerated");
if (isnull("BlackBerry_ES/AttachmentServer")) exit(0, "The host is not affected because BlackBerry Attachment Server isn't installed.");

if (
  ("Enterprise Server" >< prod &&  version !~ "4\.1\.[3-5] ") ||
  (
    "Unite!" >< prod &&
    version !~ "^(0\.|1\.0 |1\.0\.0 |1\.0\.1 \(Bundle ([0-9]|[[0-2][0-9]|3[0-5])\))"
  )
) exit(0);

# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Determine whether the workaround has been implemented.
info = "";

if (report_paranoia > 1)
{
  info = string(
    "Note, though, that Nessus did not check whether the\n",
    "workaround has been implemented because of the Report\n",
    "Paranoia setting in effect in effect when this scan was run.\n"
  );
}
else
{
  if ("Unite!" >!< prod)
  {
    key = "SOFTWARE\Research In Motion\BBAttachServer\BBAttachBESExtension";
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      item = RegQueryValue(handle:key_h, item:"BBAttachFormatList");
      if (!isnull(item))
      {
        formats = item[1];
        if ("|pdf|" >< formats) info += "  - The format extensions field includes 'pdf'." + '\n';
      }
      RegCloseKey (handle:key_h);
    }
  }

  key = "SOFTWARE\Research In Motion\BBAttachEngine\Distillers\LoadPDFDistiller";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"Enabled");
    if (!isnull(item))
    {
      enabled = item[1];
      if (enabled) info += '  - The PDF distiller is enabled.\n';
    }
    RegCloseKey (handle:key_h);
  }

  if (vuln)
  {
    if ("Unite!" >< prod || max_index(split(vuln)) > 1)
    {
      info = string(
        "Nessus has determined that the workaround described in the\n",
        "vendor's advisory has not been implemented because :\n",
        "\n",
        info
      );
    }
    else
    {
      info = string(
        "Nessus has determined that the workaround described in the\n",
        "vendor's advisory has only be partially implemented\n",
        "because :\n",
        "\n",
        info
      );
    }
  }
}
RegCloseKey(handle:hklm);
if (!info)
{
  NetUseDel();
  exit(0);
}


# Check if the patch for BlackBerry ES was applied.
vuln = FALSE;
if ("Unite!" >!< prod && !isnull(path))
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  path2 = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\", string:path);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc == 1)
  {
    dlls = make_list(
      "AttachServer\BBDecorator\BBRenderingDecorator.dll",
      "AttachServer\BBDecorator\BBXRenderingDecorator.dll",
      "AttachServer\BBDistiller\BBDM_PDF.dll"
    );

    dll_probs = "";
    foreach dll (dlls)
    {
      fh = CreateFile(
        file:path2+dll,
        desired_access:GENERIC_READ,
        file_attributes:FILE_ATTRIBUTE_NORMAL,
        share_mode:FILE_SHARE_READ,
        create_disposition:OPEN_EXISTING
      );
      if (!isnull(fh))
      {
        ver = GetFileVersion(handle:fh);
        if (ver)
        {
          if (
            ver[0] < 4 ||
            (
              ver[0] == 4 &&
              (
                ver[1] < 1 ||
                (
                  ver[1] == 1 &&
                  (
                    ver[2] < 6 ||
                    (ver[2] == 6 && ver[3] < 6)
                  )
                )
              )
            )
          )
          {
            file_version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
            dll_probs += '  - ' + dll + ' (version ' + file_version + ')\n';
            vuln = TRUE;
          }
        }
        else dll_probs += '  - ' + dll + ' (unknown version)\n';

        CloseFile(handle:fh);
      }
      else dll_probs += '  - ' + dll + ' (unable to open file)\n';
    }

    # There's no vulnerability if we could determine the DLLs have been patched.
    if (!dll_probs) info = "";
    # Otherwise if there's at least one patched file...
    else if (max_index(split(dll_probs)) < max_index(keys(dlls)))
    {
      if (max_index(split(dll_probs)) > 1) s = "s are";
      else s = " is";

      if (vuln)
      {
        info = string(
          info,
          "\n",
          "In addition, it appears that the patch has not been\n",
          "installed completely as the following file", s, " still\n",
          "vulnerable :\n",
          "\n",
          dll_probs
        );
      }
      else exit(0, "There was an issue accessing at least one of the affected DLLs.");
    }
  }
}
NetUseDel();


# Report if an issue was found.
if (info)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "  Product  : ", prod, "\n",
      "  Version  : ", version, "\n",
      "  Comments : ", str_replace(find:'\n', replace:'\n             ', string:info), "\n"
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
