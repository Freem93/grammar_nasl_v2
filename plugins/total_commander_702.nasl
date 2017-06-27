#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40927);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-4756");
  script_bugtraq_id(25581);
  script_xref(name:"OSVDB", value:"39838");
  script_xref(name:"Secunia", value:"26734");

  script_name(english:"Total Commander FTP Client Traversal Arbitrary File Overwrite");
  script_summary(english:"Checks if vulnerable version of Total Commander is installed"); 
 
  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by an
arbitrary file overwrite issue." );

  script_set_attribute(attribute:"description", value:
"The version of Total Commander installed on the remote host fails to
sanitize filenames of directory traversal sequences when downloading
files via FTP. 

If an attacker can trick a user on the affected system into visiting a
malicious FTP server, he can leverage this issue to write to arbitrary
files, subject to his privileges.");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?782ae166" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Sep/55" );
  script_set_attribute(attribute:"see_also", value:"http://www.ghisler.com/whatsnew.htm" );

  script_set_attribute(attribute:"solution", value:
"Upgrade to Total Commander 7.02 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/10");

 script_cvs_date("$Date: 2016/11/03 20:40:06 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("total_commander_installed.nasl");
  script_require_keys("SMB/Totalcommander/Version");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");


version_ui = get_kb_item("SMB/Totalcommander/Version_UI");
version    = get_kb_item("SMB/Totalcommander/Version");
if (isnull(version)) exit(1,"The 'SMB/Totalcommander/Version' KB item is missing.");

if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

ver = split(version,sep:".",keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# nb: the issue is also addressed in 6.57, which runs under Windows
#     3.1 and uses a totally different file name so it won't be
#     reported by total_commander_installed.nasl.
if (
  ver[0] < 7 ||
  (ver[0] == 7 && ver[1] == 0 && ver[2] < 2)
)
{
  port = get_kb_item("SMB/transport");
  if (report_verbosity > 0) 
  {
    report = string(
      "\n",
      "Version ",version_report," of Total Commander is installed on the remote host.",
      "\n"
    );
    security_hole(port:port, extra:report);
  }  	
  else security_hole(port);
  exit(0);
}
else exit(0, "The host is not affected since Total Commander "+version_report+" is installed.");
