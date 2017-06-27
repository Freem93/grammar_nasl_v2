#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25123);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2007-2175");
  script_bugtraq_id(23608);
  script_osvdb_id(34178);

  script_name(english:"QuickTime < 7.1.6 quicktime.util.QTHandleRef toQTPointer Method Arbitrary Code Execution (Windows)");
  script_summary(english:"Checks version of QuickTime on Windows");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is prone to
multiple attacks." );
 script_set_attribute(attribute:"description", value:
"According to its version, the installation of QuickTime on the remote
Windows host contains a bug that might allow a rogue Java program to
write anywhere in the heap. 

An attacker may be able to leverage this issue to execute arbitrary
code on the remote host by luring a victim into visiting a rogue page
containing a malicious Java applet." );
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=305446" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to QuickTime version 7.1.6 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Apple QTJava toQTPointer() Arbitrary Memory Access');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/05/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/04/24");
 script_cvs_date("$Date: 2011/04/13 16:19:07 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");
  script_dependencies("quicktime_installed.nasl");
  script_require_keys("SMB/QuickTime/Version");
  exit(0);
}


ver = get_kb_item("SMB/QuickTime/Version");
if (
  ver && 
  ver =~ "^([0-6]\.|7\.(0\.|1\.[0-5]([^0-9]|$)))"
) security_hole(get_kb_item("SMB/transport"));
