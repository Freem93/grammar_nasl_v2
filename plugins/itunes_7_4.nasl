#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25998);
  script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2015/08/03 13:57:40 $");

  script_cve_id("CVE-2007-3752");
  script_bugtraq_id(25567);
  script_osvdb_id(38528);

  script_name(english:"Apple iTunes < 7.4 Malformed Music File Heap Overflow (credentialed check)");
  script_summary(english:"Check the version of iTunes");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by a
remote code execution flaw.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Apple iTunes, a popular media player.

The remote version of iTunes is vulnerable to a heap overflow when
it parses a specially crafted MP4/AAC file.  By tricking a user into
opening such a file, a remote attacker may be able to leverage this
issue to execute arbitrary code on the affected host, subject to the
privileges of the user running the application.");
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=306404");
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes 7.4 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/07");
 script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/06");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
  script_dependencies("itunes_detect.nasl");
  script_require_keys("SMB/iTunes/Version");

  exit(0);
}


vers = get_kb_item("SMB/iTunes/Version");
if ( isnull(vers) ) exit(0);
vers = split(vers, sep:'.', keep:FALSE);
if ( int(vers[0]) > 0 && (
     int(vers[0]) < 7 ||
     (int(vers[0]) == 7 && int(vers[1]) < 4 ) ) )
	security_hole(get_kb_item("SMB/transport"));
