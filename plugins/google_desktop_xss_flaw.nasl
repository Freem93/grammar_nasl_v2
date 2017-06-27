#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) 
{
  script_id(24710);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2007-1085");	
  script_bugtraq_id(22650);
  script_osvdb_id(33483);
  script_xref(name:"CERT", value:"615857");

  script_name(english:"Google Desktop Advanced Search Internal Web Server XSS");
  script_summary(english:"Checks version of Google Desktop"); 

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is vulnerable to a
local cross-site scripting attack." );
 script_set_attribute(attribute:"description", value:
"The version of Google Desktop installed on the remote host is affected
by a cross-site scripting flaw because it fails to properly encode the
output for the 'under' keyword.  This issue cannot be directly
exploited remotely; however, when used in conjunction with a known
Google.com cross-site scripting vulnerability to extract the unique
signature associated with Google Desktop software, it might allow an
attacker to query a victim's system for sensitive information." );
  
  # http://web.archive.org/web/20110104102242/http://desktop.google.com/support/bin/answer.py?answer=14280
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?72d01fea" );
 script_set_attribute(attribute:"solution", value:
"Google Desktop automatically updates itself when a new version of the
software is available.  However, in some cases it may not be able to
update itself due to network connectivity issues.  Please ensure that
Google Desktop version 5.0.0701.30540 or later is installed." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/02/22");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/02/21");
 script_cvs_date("$Date: 2016/05/16 14:02:51 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe",value:"cpe:/a:google:desktop");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_dependencies("google_desktop_installed.nasl");
  script_require_keys("SMB/Google/Google Dektop/version");
  script_require_ports(139, 445);
  exit(0);
}

#

include("global_settings.inc");

ver = get_kb_item("SMB/Google/Google Dektop/version");
ver = split(ver, sep:".",keep:FALSE);

if (!isnull(ver))
  {
    fix = split("5.0.701.30540", sep:'.', keep:FALSE);
    for (i=0; i<4; i++)
      fix[i] = int(fix[i]);

    for (i=0; i<max_index(ver); i++)
     { 	
      if ((ver[i] < fix[i]))
      {
        security_hole(get_kb_item("SMB/transport"));
	exit(0);
      }
      else if (ver[i] > fix[i])
        break;
     }
  }
