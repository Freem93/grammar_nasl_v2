#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11336);
 script_version("$Revision: 1.78 $");
 script_cvs_date("$Date: 2017/05/24 21:06:47 $");

 script_cve_id(
   "CVE-2002-0616",
   "CVE-2002-0617",
   "CVE-2002-0618",
   "CVE-2002-0619"
 );
 script_bugtraq_id(
   4821,
   5063,
   5064,
   5066
 );
 script_osvdb_id(
   5171,
   5173,
   5174,
   5175
 );
 script_xref(name:"MSFT", value:"MS02-031");
 script_xref(name:"MSKB", value:"324458");

 script_name(english:"MS02-031: Cumulative patches for Excel and Word for Windows (324458)");
 script_summary(english:"Determines the version of WinWord.exe and Excel.exe.");

 script_set_attribute(attribute:"synopsis", value:
"A Microsoft Office application installed on the remote host is
affected by multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The versions of Microsoft Word and Excel installed on the remote
host are missing a security update. They are, therefore, affected by
multiple vulnerabilities :

  - A security bypass vulnerability exists in Excel due to
    improper handling of formatted inline macros that are
    attached to objects within a workbook. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to open a specially crafted workbook,
    to execute macros outside the constraints of the Macro
    Security Model. (CVE-2002-0616)

  - A security bypass vulnerability exists in Excel due to
    improper handling of macros in a workbook when it is
    opened through a hyperlink associated with a drawing
    shape in another workbook. An unauthenticated, remote
    attacker can exploit this, by convincing a user to open
    a specially crafted workbook, to execute macros outside
    the constraints of the Macro Security Model.
    (CVE-2002-0617)

  - A flaw exists in the Macro Security Model in Excel due
    to a failure to correctly detect the presence of HTML
    scripting within an Excel workbook that contains an XSL
    stylesheet. An unauthenticated, remote attacker can
    exploit this, by convincing a user to open a specially
    crafted file, to execute arbitrary HTML scripts.
    (CVE-2002-0618)

  - A flaw exists in Word when opening Mail Merge documents
    that have been saved in HTML format. An unauthenticated,
    remote attacker can exploit this, by convincing a user
    to open a specially crafted document, to execute
    arbitrary VBA code in Access. (CVE-2002-0619)");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms02-031");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Excel 2000, Excel 2002,
and Word 2002.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:ND");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/04/08");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/06/19");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows : Microsoft Bulletins");

 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');

 exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS02-031';
kb = '324458';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

arch = get_kb_item_or_exit("SMB/ARCH");
rootfiles = hotfix_get_officeprogramfilesdir();
if ( ! rootfiles ) exit(0, "Failed to get Office Program Files directory.");

if (arch == "x64")
{
  rootfiles2 = hotfix_get_programfilesdirx86();
  if (!rootfiles2) exit(1, "Failed to get the Program Files (x86) directory.");
  rootfiles = make_list(rootfiles, rootfiles2);
}
rootfiles = list_uniq(make_list(rootfiles));

product_file["Access"] = "MsAccess.exe";
product_file["Word"] = "WinWord.exe";
product_file["WordCnv"] = "Wordconv.exe";
product_file["WordViewer"] = "Wordview.exe";
product_file["Excel"] = "Excel.exe";
product_file["ExcelCnv"] = "Excelcnv.exe";
product_file["ExcelViewer"] = "Xlview.exe";
product_file["PowerPoint"] = "PowerPnt.exe";
product_file["PowerPointViewer"] = "Pptview.exe";
product_file["PowerPointCnv"] = "Ppcnvcom.exe";
product_file["Publisher"] = "Mspub.exe";
product_file["Project"] = "WinProj.exe";
product_file["OneNote"] = "OneNote.exe";
product_file["InfoPath"] = "Infopath.exe";
product_file["Groove"] = "Groove.exe";
product_file["FrontPage"] = "Frontpg.exe";
product_file["SharePointDesigner"] = "Spdesign.exe";
product_file["Visio"] = "Visio.exe";
product_file["VisioViewer"] = "vviewer.dll";
product_file["Lync"] = "Lync.exe";
product_file["Outlook"] = "Outlook.exe";

products = make_list("Access", "Word", "WordCnv", "WordViewer", "Excel", "ExcelCnv", "ExcelViewer", "PowerPoint", "PowerPointViewer", "PowerPointCnv", "Publisher", "Project", "OneNote", "InfoPath", "Groove", "FrontPage", "SharePointDesigner", "Visio", "VisioViewer", "Lync", "Outlook");
paths = make_list("root\Office16", "Office16", "Office15", "Office14", "Office12", "Office11", "Office10", "Office", "PowerPoint Viewer", "Visio10", "Visio11", "Visio12", "Visio", "Visio2000", "Visio Viewer");

# Older versions of Office products sometimes install in Program Files or
# Program Files (x86), outside the Microsoft Office folder
product_file_progfiles["PowerPointViewer"] = "ppview32.exe";
product_file_progfiles["WordViewer"] = "Wordview.exe";
product_file_progfiles["ExcelViewer"] = "Xlview.exe";

paths_progfiles = make_list("PowerPoint Viewer", "WordView", "Xlview");

login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();
port   = kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

share = '';
lastshare = '';
office_product_version_found = FALSE;
foreach rootfile (rootfiles)
{
  share = hotfix_path2share(path:rootfile);
  if (isnull(share)) continue;

  if (share != lastshare)
  {
    NetUseDel(close:FALSE);
    r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (r != 1) continue;
  }
  foreach product (products)
  {
    foreach path (paths)
    {
      current_product_file = product_file[product];

      file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft Office\" + path + "\" + current_product_file, string:rootfile);

      handle =  CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
      if ( ! isnull(handle) )
      {
        v =  GetFileVersion(handle:handle);
        CloseFile(handle:handle);
        if (product == 'PowerPoint' && int(v[0]) >= 14)
        {
          # Set the powerpoint version to the larger of ppcore.dll and powerpoint.exe
          file = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\Microsoft Office\" + path + "\" + 'ppcore.dll', string:rootfile);

          handle = CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
          if (!isnull(handle))
          {
            v2 = GetFileVersion(handle:handle);
            CloseFile(handle:handle);
            if (isnull(v) || (!isnull(v) && !isnull(v2) && ver_compare(ver:v, fix:v2) <= 0))
            {
              v = v2;
              current_product_file = "ppcore.dll";
            }
          }
        }

        if (product == "Visio" && isnull(v))
        {
          # Older versions of Visio included Visio32.exe or Visio16.exe rather than Visio.exe
          file = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\Microsoft Office\" + path + "\" + 'Visio32.exe', string:rootfile);
          handle = CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
          if (!isnull(handle))
          {
            v = GetFileVersion(handle:handle);
            CloseFile(handle:handle);
            if (!isnull(v))
              current_product_file = "Visio32.exe";
            else
            {
              file = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\Microsoft Office\" + path + "\" + 'Visio16.exe', string:rootfile);
              handle = CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
              if (!isnull(handle))
              {
                v = GetFileVersion(handle:handle);
                CloseFile(handle:handle);
                if (!isnull(v))
                  current_product_file = "Visio16.exe";
              }
            }
          }
        }

        if (product == "Visio" && int(v[0]) == "11" && ver_compare(ver:v, fix:"11.0.5509.0") < 0)
        {
          # Visio 2003 SP1 does not update Visio.exe, so for Visio.exe versions below SP2 we need to check Vislib.dll
          file = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\Microsoft Office\" + path + "\" + 'Vislib.dll', string:rootfile);
          handle = CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
          if (!isnull(handle))
          {
            v2 = GetFileVersion(handle:handle);
            CloseFile(handle:handle);
            if (isnull(v) || (!isnull(v) && !isnull(v2) && ver_compare(ver:v, fix:v2) <= 0))
            {
              v = v2;
              current_product_file = "Vislib.dll";
            }
          }
        }

        if (product == "PowerPointViewer" && int(v[0]) == 12 && ver_compare(ver:v, fix:"12.0.6211.1000") >= 0 && ver_compare(ver:v, fix:"12.0.6600.1000") < 0)
        {
          # PowerPoint Viewer 2007 SP2 does not update pptview.exe, so versions between 12.0.6211.1000 (SP1)
          # and 12.0.6600.1000 (SP3) could be SP1 or SP2
          # We need to check ppcnvcom.exe instead

          file = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\Microsoft Office\" + path + "\" + 'ppcnvcom.exe', string:rootfile);
          handle = CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
          if (!isnull(handle))
          {
            v2 = GetFileVersion(handle:handle);
            CloseFile(handle:handle);
            if (isnull(v) || (!isnull(v) && !isnull(v2) && ver_compare(ver:v, fix:v2) <= 0))
            {
              v = v2;
               current_product_file = "ppcnvcom.exe";
            }
          }
        }

        if ( ! isnull(v) )
        {
          product_path = rootfile + "\Microsoft Office\" + path + "\" + current_product_file;
          version = join(v, sep:'.');
          set_kb_item(name:"SMB/Office/" + product + "/" + version + "/ProductPath", value:product_path);
          office_product_version_found = TRUE;
        }
      }
    }
  }

  # For older Office installations outside the Microsoft Office folder
  foreach product(keys(product_file_progfiles))
  {
    foreach path (paths_progfiles)
    {
      current_product_file = product_file_progfiles[product];
      file = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\" + path + "\" + current_product_file, string:rootfile);
      handle = CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
      if (!isnull(handle))
      {
        v = GetFileVersion(handle:handle);
        CloseFile(handle:handle);

        # PowerPoint Viewer 97/2000/2002 uses ppview32.exe or ppview16.exe
        if (product == "PowerPointViewer" && isnull(v))
        {
          file = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\" + path + "\" + 'ppview16.exe', string:rootfile);
          handle = CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
          if (!isnull(handle))
          {
            v = GetFileVersion(handle:handle);
            CloseFile(handle:handle);
            if (!isnull(v))
              current_product_file = "ppview16.exe";
          }
        }

        if ( ! isnull(v))
        {
          product_path = rootfile + "\" + path + "\" + current_product_file;
          version = join(v, sep:'.');
          set_kb_item(name:"SMB/Office/" + product + "/" + version + "/ProductPath", value:product_path);
          office_product_version_found = TRUE;
        }
      }
    }
  }
}

NetUseDel();

if (office_product_version_found)
  set_kb_item(name:"SMB/Office/ProductPath/Enumerated", value:TRUE);

report = NULL;
list = get_kb_list("SMB/Office/Excel/*/ProductPath");
if (!isnull(list))
{
  foreach item (keys(list))
  {
    excel_version = item - 'SMB/Office/Excel/' - '/ProductPath';
    if ( ! isnull(excel_version) )
    {
      excel_version = split(excel_version, sep:'.');
      if ( excel_version[0] == 9 && excel_version[1] == 0 && excel_version[2] == 0 && excel_version[3] < 6508 )
        report += '\nExcel version installed : '+join(excel_version, sep:'.')+'\nFixed version : 9.0.0.6508\n';
      else if ( excel_version[0] == 10 && excel_version[1] == 0 && excel_version[2] < 4109 )
        report += '\nExcel version installed : '+join(excel_version, sep:'.')+'\nFixed version : 10.0.4109.0\n';
    }
  }
}

list = get_kb_list("SMB/Office/Word/*/ProductPath");
if (!isnull(list))
{
  foreach item (keys(list))
  {
    word_version = item - 'SMB/Office/Word/' - '/ProductPath';
    if ( ! isnull(word_version) )
    {
      word_version = split(word_version, sep:'.');
      if ( word_version[0] == 10 && word_version[1] == 0 && (word_version[2] < 4009 || (word_version[2] == 4009 && word_version[3] < 3501)) )
        report += '\nWord version installed : '+join(word_version, sep:'.')+'\nFixed version : 10.0.4009.3501\n';
    }
  }
}

if (!isnull(report))
{
   set_kb_item(name:"SMB/Missing/MS02-031", value:TRUE);
   hotfix_add_report(report, bulletin:bulletin, kb:kb);
   hotfix_security_hole();
}
else audit(AUDIT_HOST_NOT, 'affected');
