#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(47762);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/08/03 13:57:41 $");

  script_cve_id("CVE-2010-1777");
  script_bugtraq_id(41789);
  script_osvdb_id(66456);

  script_name(english:"Apple iTunes < 9.2.1 'itpc:' Buffer Overflow (credentialed check)");
  script_summary(english:"Checks version of iTunes on Windows");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains an application that is affected by a buffer
overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Apple iTunes installed on the remote Windows host is
older than 9.2.1. Such versions may be affected by a buffer overflow
vulnerability in the handling of 'itpc:' URLs that could allow an
attacker to execute arbitrary code on the remote host. 

To exploit this vulnerability, an attacker would need to send a
malformed itpc: link to user on the remote host and wait for him to
click on it.");

  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT4263"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Apple iTunes 9.2.1 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/20");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("itunes_detect.nasl");
  script_require_keys("SMB/iTunes/Version");

  exit(0);
}


include ("global_settings.inc");


version = get_kb_item("SMB/iTunes/Version");
if (isnull(version)) exit(1, "The 'SMB/iTunes/Version' KB item is missing.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 9 ||
  (
    ver[0] == 9 && 
    (
      ver[1] < 2 ||
      (ver[1] == 2 && ver[2] < 1) ||
      (ver[1] == 2 && ver[2] == 1 && ver[3] < 4)
    )
  )
)
{
  if (report_verbosity > 0)
  {
    report = '\n' +
      'iTunes ' + version + ' is installed on the remote host.\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0, "The host is not affected since iTunes "+version+" is installed.");
