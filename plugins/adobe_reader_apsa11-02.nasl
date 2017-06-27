#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(53451);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");
  
  script_cve_id("CVE-2011-0610", "CVE-2011-0611");
  script_bugtraq_id(47314, 47531);
  script_osvdb_id(71686, 71912);
  script_xref(name:"CERT", value:"230057");
  script_xref(name:"Secunia", value:"44149");
  
  script_name(english:"Adobe Reader 9.x / 10.x Multiple Vulnerabilities (APSB11-08)");
  script_summary(english:"Checks version of Adobe Reader");
 
  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader on the remote Windows host is affected by
multiple memory corruption vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of Adobe Reader 9.x <
9.4.4 or 10.x <= 10.1.  Such versions are affected by multiple
memory corruption vulnerabilities.

A remote attacker could exploit this by tricking a user into viewing
a maliciously crafted PDF file, resulting in arbitrary code
execution. 

Note that Adobe Reader X Protected Mode prevents an exploit of this
kind from executing. 

Note also, CVE-2011-0611 is being exploited in the wild as of April
2011.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ee82b34");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/advisories/apsa11-02.html");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-08.html");
  # "The update for Adobe Reader X (10.x) for Windows also incorporate the updates
  # previously addressed in all other supported versions of Adobe Reader and Acrobat
  # as noted in Security Bulletin APSB11-06 and Security Bulletin APSB11-08."
  script_set_attribute(attribute:"see_also",value:"http://www.adobe.com/support/security/bulletins/apsb11-16.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader 9.4.4 / 10.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player 10.2.153.1 SWF Memory Corruption Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value: "2011/04/11");
  script_set_attribute(attribute:"patch_publication_date", value: "2011/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/15");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("adobe_reader_installed.nasl");
  script_require_keys("SMB/Acroread/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

version = get_kb_item_or_exit("SMB/Acroread/Version");
path = get_kb_item_or_exit('SMB/Acroread/'+version+'/Path');

version_ui = get_kb_item('SMB/Acroread/'+version+'/Version_UI');
if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# This affects 9.x < 9.4.4 / 10.x < 10.1
if (
  # 9.x
  (
    (ver[0] == 9 && ver[1] < 4) ||
    (ver[0] == 9 && ver[1] == 4 && ver[2] < 4)
  )
  ||
  # 10.x
  (ver[0] == 10 && ver[1] < 1)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : '+path+
      '\n  Installed version : '+version_report+
      '\n  Fixed version     : 9.4.4 / 10.1\n';
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(get_kb_item('SMB/transport'));
}
else exit(0, 'Adobe Reader '+version_report+' is installed and not affected.');
