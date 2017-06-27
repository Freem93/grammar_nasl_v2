#
# This script was written by Jeff Adams <jadams@netcentrics.com>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, OSVDB ref, output formatting (9/23/09)
# - Title standardization (9/27/09)


include("compat.inc");

if(description)
{
 script_id(12226);
 script_version("$Revision: 1.20 $");
 script_cve_id("CVE-2004-0431");
 script_bugtraq_id(10257);
 script_osvdb_id(5745);
 
 script_name(english:"QuickTime < 6.5.1 .mov File sample-to-chunk Table Data Handling Overflow (Windows)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a media player installed that is affected
by a remote code execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is using QuickTime, a popular media player/Plug-in
that handles many Media files.

This version has a Heap overflow that could allow an attacker
to execute arbitrary code on this host, with the rights of the user
running QuickTime." );
 script_set_attribute(attribute:"see_also", value:"http://eeye.com/html/Research/Advisories/AD20040502.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to QuickTime version 6.5.1 or higher." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/05/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/05/02");
 script_cvs_date("$Date: 2011/12/16 22:59:43 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/05/02");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
script_end_attributes();
 script_summary(english:"Determines the version of QuickTime Player/Plug-in");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Jeff Adams");
 script_family(english:"Windows");
 script_dependencies("quicktime_installed.nasl");
 script_require_keys("SMB/QuickTime/Version");
 exit(0);
}


ver = get_kb_item("SMB/QuickTime/Version");
if (ver && ver =~ "^([0-5]\.|6\.[0-4]\.|6\.5$|6.5.0$)") security_warning(get_kb_item("SMB/transport"));
