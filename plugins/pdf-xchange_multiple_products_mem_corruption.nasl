#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3000 ) exit(0);

include("compat.inc");

if (description)
{
  script_id(44048);
  script_version("$Revision: 1.6 $");

  script_bugtraq_id(37582);
  script_osvdb_id(61459);
  script_xref(name:"Secunia", value:"37706");

  script_name(english:"PDF-XChange Viewer/PDF-XChange PDF File Handling Memory Corruption");
  script_summary(english:"Checks for vulnerable versions of PDF-XChange/PDF-XChange Viewer software."); 

  script_set_attribute(attribute:"synopsis", value:
"It may be possible to execute arbitrary code on the remote system."
  );
  script_set_attribute(attribute:"description", value:
"A version of PDF-XChange Viewer, PDF-XChange PDF Viewer SDK or
PDF-XChange installed on the remote host fails to validate input while
opening certain specially crafted PDF files. 

By tricking users into opening a malicious PDF file, a remote attacker
could exploit this flaw to execute arbitrary code on the remote
system."
  );
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2009-64/" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/Jan/23" );
  script_set_attribute(attribute:"see_also", value:"http://www.docu-track.com/news/show/80" );

  script_set_attribute(attribute:"solution", value:
"Upgrade to :

  -  PDF-XChange Viewer/PDF-XChange PDF Viewer SDK 2.0 Build 44 (2.044) or later.
  -  PDF-XChange 4.0 Build 174 (4.0174) or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/18");

 script_cvs_date("$Date: 2016/11/02 14:37:08 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("pdf-xchange_installed.nasl");

  script_require_ports("SMB/Tracker_Software/PDF-XChange Viewer/Installed", 
                       "SMB/Tracker_Software/PDF-XChange PDF Viewer SDK/Installed",
                       "SMB/Tracker_Software/PDF-XChange Standard/Installed",
                       "SMB/Tracker_Software/PDF-XChange Pro/Installed",
                       "SMB/Tracker_Software/PDF-XChange Lite/Installed", 
                       139,445);

  exit(0);
}

include("global_settings.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1,"The 'SMB/Registry/Enumerated' KB item is missing.");

info = "";
info2 = "";

installs = get_kb_list("SMB/Tracker_Software/*");
if (isnull(installs))  exit(0,"The 'SMB/Tracker_Software/*' KBs are missing.");

foreach install (keys(installs))
{
  if("/Installed" >< install) continue;
 
  if(ereg(pattern:"^SMB/Tracker_Software/.+/[0-9.]+$",string:install))
  {
    product = version = NULL;
    matches = eregmatch(pattern:"^SMB/Tracker_Software/(.+)/([0-9.]+)$",string:install) ; 
    if(matches)
    {
      product = matches[1];
      version = matches[2]; 
 
      if(product && version)   
      {
        if (ereg(pattern:"^PDF-XChange (Standard|Lite|Pro)$",string:product))
         fixed_version = "4.0.174";
        else
         fixed_version  = "2.0.44";

        if(fixed_version != version)
        {
          fix = split(fixed_version, sep:'.', keep:FALSE);
          for (i=0; i<max_index(fix); i++)
            fix[i] = int(fix[i]);
  
          ver = split(version, sep:".",keep:FALSE);
          for (i=0; i<max_index(ver); i++)
            ver[i] = int(ver[i]);
   
          for (i=0; i<max_index(ver); i++)
          if ((ver[i] < fix[i]))
          {
            version_ui       =  ver[0] + "." + ver[1]  + " Build " + ver[2];
            fixed_version_ui =  fix[0] + "." + fix[1]  + " Build " + fix[2];
 
            info += 
              "Product Name      : " + product  + '\n' +
              "Installation Path : " + installs[install] + '\n' +
              "Installed version : " + version_ui + '\n' + 
              "Fixed version     : " + fixed_version_ui + '\n\n';
          }
          else if (ver[i] > fix[i])
          {
            info2 += product + " version " + version + ", under " + installs[install] + ". ";
            break;
          }
        }
        else
          info2 += product + " version " + version + ", under " + installs[install] + '. ';
      }
    } 
  }
}

# Report vulnerable installs

if (info)
{
  if (report_verbosity > 0)
  {
   if (max_index(split(info,sep:'\n\n',keep:FALSE)) > 1) s = "s of PDF-XChange or  or PDF-XChange Viewer are";
      else s = " of PDF-Xchange or PDF-XChange Viewer is";

    report = '\n' +
      'The following vulnerable instance' + s + ' installed :' + '\n' +
      '\n' +
      info ;

    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));

  exit(0);
}
if(info2)
 exit(0,"Following instance(s) of PDF-XChange/PDF-XChange Viewer are installed and are not vulnerable : "+ info2);
  
