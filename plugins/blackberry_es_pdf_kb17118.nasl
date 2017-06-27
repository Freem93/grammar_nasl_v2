#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35430);
  script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_cve_id("CVE-2009-0176", "CVE-2009-0219");
  script_bugtraq_id(33224, 33248, 33250);
  script_osvdb_id(52001);
  script_xref(name:"Secunia", value:"33534");

  script_name(english:"BlackBerry Enterprise Server / Unite! PDF Distiller Component Vulnerabilities (KB17118 / KB17119)");
  script_summary(english:"Checks version and looks for workaround");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by several
vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The version of BlackBerry Enterprise Server / BlackBerry Unite! on the
remote host reportedly contains several vulnerabilities in the PDF
distiller component of the BlackBerry Attachment Service :

  - A heap-based buffer overflow triggered when parsing a
    certain stream inside a PDF file.

  - A heap-based buffer overflow triggered when parsing a
    data stream inside of a PDF file.

  - An uninitialized memory vulnerability triggered when
    when parsing a data stream inside of a PDF file.

A remote attacker may be able to leverage these issues to execute
arbitrary code on the affected host subject to the privileges under
which the application runs, generally 'SYSTEM', by sending an email
message with a specially crafted PDF file and having that opened for
viewing on a BlackBerry smartphone.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3319be28");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7cb4b343" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc1633bf" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/500011/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/500015/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/500016/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.blackberry.com/btsc/viewContent.do?externalId=KB17118" );
 script_set_attribute(attribute:"see_also", value:"http://www.blackberry.com/btsc/viewContent.do?externalId=KB17119" );
 script_set_attribute(attribute:"solution", value:
"If using BlackBerry Enterprise Server, apply Interim Security Software
Update 2 or later or prevent the Attachment Service from processing
PDF files.

If using BlackBerry Unite!, either upgrade to 1.0.3 bundle 28 or later
or prevent the Attachment Service from processing PDF files.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 399);

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/20");

script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rim:blackberry_enterprise_server");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("blackberry_es_installed.nasl", "smb_hotfixes.nasl");
  script_require_keys("BlackBerry_ES/Product", "BlackBerry_ES/Path", "BlackBerry_ES/Version", "SMB/Registry/Enumerated", "BlackBerry_ES/AttachmentServer");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");
include("audit.inc");

prod = get_kb_item_or_exit("BlackBerry_ES/Product");
version = get_kb_item_or_exit("BlackBerry_ES/Version");
if (isnull(get_kb_item("BlackBerry_ES/AttachmentServer"))) exit(0, "The host is not affected because BlackBerry Attachment Server is not installed.");

# Exit unless it looks like a vulnerable version.
if (
  ("Enterprise Server" >< prod &&  version !~ "4\.1\.[3-6] ") ||
  (
    "Unite!" >< prod &&
    version !~ "^(0\.|1\.0 |1\.0\.[0-2] |1\.0\.3 \(Bundle ([0-9]|[[0-1][0-9]|2[0-7])\))"
  )
) exit(0);


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


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

  if (info)
  {
    if ("Unite!" >< prod || max_index(split(info)) > 1)
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
path = get_kb_item("BlackBerry_ES/Path");
vuln=FALSE;
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
                    (ver[2] == 6 && ver[3] < 12)
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
      else exit(1, "There was an issue accessing at least one of the affected DLLs.");
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
