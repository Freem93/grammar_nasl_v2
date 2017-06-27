#
# This script was written by John Lampe...j_lampe@bellsouth.net 
# Some entries were added by David Maciejak <david dot maciejak at kyxar dot fr>
#
# See the Nessus Scripts License for details

# Changes by Tenable:
# - Revised plugin title, moved CVE from header comment to CVE (4/9/2009)

include("compat.inc");

if(description)
{
 script_id(11748);
 script_version ("$Revision: 1.34 $");

 script_cve_id(
  "CVE-1999-0934",
  "CVE-1999-0935",
  "CVE-1999-0937",
  "CVE-1999-1072",
  "CVE-1999-1374",
  "CVE-1999-1377",
  "CVE-2000-0288",
  "CVE-2000-0423",
  "CVE-2000-0526",
  "CVE-2000-0923",
  "CVE-2000-0952",
  "CVE-2000-0977",
  "CVE-2000-1023",
  "CVE-2000-1131",
  "CVE-2000-1132",
  "CVE-2001-0022",
  "CVE-2001-0023",
  "CVE-2001-0076",
  "CVE-2001-0099",
  "CVE-2001-0100",
  "CVE-2001-0123",
  "CVE-2001-0133",
  "CVE-2001-0135",
  "CVE-2001-0180",
  "CVE-2001-0420",
  "CVE-2001-0562",
  "CVE-2001-1100",
  "CVE-2001-1196",
  "CVE-2001-1205",
  "CVE-2001-1212",
  "CVE-2001-1283",
  "CVE-2001-1343",
  "CVE-2002-0203",
  "CVE-2002-0230",
  "CVE-2002-0263",
  "CVE-2002-0346",
  "CVE-2002-0611",
  "CVE-2002-0710",
  "CVE-2002-0749",
  "CVE-2002-0750",
  "CVE-2002-0751",
  "CVE-2002-0752",
  "CVE-2002-0917",
  "CVE-2002-0955",
  "CVE-2002-1334",
  "CVE-2002-1334",
  "CVE-2002-1526",
  "CVE-2003-0153"
 );
 script_bugtraq_id(
  1784,
  2177,
  2197,
  4211,
  4579,
  5078,
  6265
 );
 script_osvdb_id(
  1602,
  1614,
  1642,
  1646,
  1669,
  1673,
  1700,
  2002,
  3486,
  3546,
  3568,
  3589,
  4572,
  4971,
  5459,
  5462,
  5463,
  6165,
  6326,
  6486,
  6504,
  6505,
  6506,
  6507,
  6763,
  6809,
  6810,
  6811,
  7161,
  7162,
  7715,
  7968,
  8393,
  8661,
  8737,
  8959,
  8960,
  9234,
  9283,
  9284,
  9859,
  10844,
  10847,
  10875,
  11897,
  13120,
  13121,
  13125,
  13683,
  13687,
  13750,
  14498,
  58525
 );
 
 script_name(english:"Multiple Dangerous CGI Script Detection");
 script_summary(english:"Checks for dangerous cgi scripts");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server may contain some dangerous CGI scripts."
 );
 script_set_attribute(attribute:"description", value:
"It is possible that the remote web server contains one or more
dangerous CGI scripts. 

Note that this plugin does not actually test for the underlying flaws
but instead only searches for scripts with the same name as those with
known vulnerabilities."
 );
 script_set_attribute(attribute:"solution", value:
"Visit http://cve.mitre.org/ and check the associated CVE entry for
each script found.  If you are running a vulnerable version, then
delete or upgrade the script."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22);
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/01/07");
 script_cvs_date("$Date: 2017/02/21 14:37:42 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_ATTACK); 
 
 script_copyright(english:"This script is Copyright (C) 2003-2017 John Lampe");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ThoroughTests", "Settings/ParanoidReport");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 || ! thorough_tests )
 exit(0, "This plugin is slow and prone to FP: it will only run in 'paranoid' mode and if the 'Perform thorough tests' setting enabled.");

port = get_http_port(default:80);
if ( get_kb_item("www/no404/" + port ) || ! port) exit(0);

if(!get_port_state(port))exit(0);
cgi[0] = "AT-admin.cgi";     cve[0] = "CVE-1999-1072";
cgi[1] = "CSMailto.cgi";     cve[1] = "CVE-2002-0749"; # and CVE-2002-0750, CVE-2002-0751, and CVE-2002-0752
cgi[2] = "UltraBoard.cgi";   cve[2] = "CVE-2001-0135";
cgi[3] = "UltraBoard.pl";    cve[3] = cve[2];
cgi[4] = "YaBB.cgi";         cve[4] = "CVE-2002-0955";
cgi[5] = "a1disp4.cgi";      cve[5] = "CVE-2001-0562";
cgi[6] = "alert.cgi";        cve[6] = "CVE-2002-0346";
cgi[7] = "authenticate.cgi"; cve[7] = "CVE-2000-0923";
cgi[8] = "bbs_forum.cgi";    cve[8] = "CVE-2001-0123";
cgi[9] = "bnbform.cgi";      cve[9] = "CVE-1999-0937";
cgi[10] = "bsguest.cgi";     cve[10] = "CVE-2001-0099";
cgi[11] = "bslist.cgi";      cve[11] = "CVE-2001-0100";
cgi[12] = "catgy.cgi";       cve[12] = "CVE-2001-1212";
cgi[13] = "cgforum.cgi";     cve[13] = "CVE-2000-1132";
cgi[14] = "classifieds.cgi"; cve[14] = "CVE-1999-0934";
cgi[15] = "csPassword.cgi";  cve[15] = "CVE-2002-0917";
cgi[16] = "cvsview2.cgi"  ;  cve[16] = "CVE-2003-0153";    
cgi[17] = "cvslog.cgi";      cve[17] = cve[16];
cgi[18] = "multidiff.cgi";   cve[18] = "CVE-2003-0153";
cgi[19]	= "dnewsweb.cgi";    cve[19] = "CVE-2000-0423";
cgi[20] = "download.cgi";    cve[20] = "CVE-1999-1377";
cgi[21] = "edit_action.cgi"; cve[21] = "CVE-2001-1196";
cgi[22] = "emumail.cgi";     cve[22] = "CVE-2002-1526";
cgi[23] = "everythingform.cgi"; cve[23] = "CVE-2001-0023";
cgi[24] = "ezadmin.cgi";     cve[24] = "CVE-2002-0263";
cgi[25] = "ezboard.cgi";     cve[25] = "CVE-2002-0263";
cgi[26] = "ezman.cgi";       cve[26] = cve[25];
cgi[27] = "ezadmin.cgi";     cve[27] = cve[25];
cgi[28] = "FileSeek.cgi";    cve[28] = "CVE-2002-0611";
cgi[29] = "fom.cgi";         cve[29] = "CVE-2002-0230";
cgi[30] = "gbook.cgi";	     cve[30] = "CVE-2000-1131";
cgi[31] = "getdoc.cgi";	     cve[31] = "CVE-2000-0288";
cgi[32] = "global.cgi";	     cve[32] = "CVE-2000-0952";
cgi[33] = "guestserver.cgi"; cve[33] = "CVE-2001-0180";
cgi[34] = "imageFolio.cgi";  cve[34] = "CVE-2002-1334";
cgi[35] = "lastlines.cgi";   cve[35] = "CVE-2001-1205";
cgi[36] = "mailfile.cgi";    cve[36] = "CVE-2000-0977";
cgi[37] = "mailview.cgi";    cve[37] = "CVE-2000-0526";
cgi[38] = "sendmessage.cgi"; cve[38] = "CVE-2001-1100";
cgi[39] = "nsManager.cgi";   cve[39] = "CVE-2000-1023";
cgi[40] = "perlshop.cgi";    cve[40] = "CVE-1999-1374";
cgi[41] = "readmail.cgi";    cve[41] = "CVE-2001-1283";
cgi[42] = "printmail.cgi";   cve[42] = cve[41];
cgi[43] = "register.cgi";    cve[43] = "CVE-2001-0076";
cgi[44] = "sendform.cgi";    cve[44] = "CVE-2002-0710";
cgi[45] = "sendmessage.cgi"; cve[45] = "CVE-2001-1100";
cgi[46] = "service.cgi";     cve[46] = "CVE-2002-0346";
cgi[47] = "setpasswd.cgi";   cve[47] = "CVE-2001-0133";
cgi[48] = "simplestmail.cgi"; cve[48] = "CVE-2001-0022";
cgi[49] = "simplestguest.cgi"; cve[49] = cve[48];
cgi[50] = "talkback.cgi";    cve[50] = "CVE-2001-0420";
cgi[51] = "ttawebtop.cgi";   cve[51] = "CVE-2002-0203";
cgi[52] = "ws_mail.cgi";     cve[52] = "CVE-2001-1343";
cgi[53] = "survey.cgi";      cve[53] = "CVE-1999-0936";
cgi[54] = "rxgoogle.cgi";    cve[54] = "CVE-2004-0251";
cgi[55] = "ShellExample.cgi"; cve[55] = "CVE-2004-0696";
cgi[56] = "Web_Store.cgi";   cve[56] = "CVE-2004-0734";
cgi[57] = "csFAQ.cgi";      cve[57] = "CVE-2004-0665";

flag = 0;
directory = "";

mymsg = string("\n", "The following dangerous CGI scripts were found :", "\n\n");

for (i = 0 ; cgi[i]; i = i + 1) {
	foreach dir (cgi_dirs()) {
   		if(is_cgi_installed_ka(item:string(dir, "/", cgi[i]), port:port)) {
  			flag = 1;
			mymsg = mymsg + string("  - ", dir, "/", cgi[i], " (", cve[i], ")\n");
   		} 
	}
} 


if (flag) {
 security_hole(port:port, extra:mymsg); 
}
