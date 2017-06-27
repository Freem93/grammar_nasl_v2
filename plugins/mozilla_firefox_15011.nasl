#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(24875);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2007-1562");
  script_bugtraq_id(23082);
  script_osvdb_id(43498);

  script_name(english:"Firefox < 1.5.0.11 / 2.0.0.3 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that can be manipulated
remotely for network abuse." );
 script_set_attribute(attribute:"description", value:
"The FTP client support in the installed version of Firefox has a flaw
that could allow a remote attacker with control of an FTP server to
perform a rudimentary port scan of, for example, the user's internal
network." );
 script_set_attribute(attribute:"see_also", value:"http://bindshell.net/papers/ftppasv" );
 script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2007/mfsa2007-11.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox 1.5.0.11 / 2.0.0.3 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/03/23");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/03/20");
 script_cvs_date("$Date: 2016/05/16 14:12:50 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

#

include("misc_func.inc");

ver = read_version_in_kb("Mozilla/Firefox/Version");
if (isnull(ver)) exit(0);

if (
  ver[0] < 1 ||
  (
    ver[0] == 1 &&
    (
      ver[1] < 5 ||
      (ver[1] == 5 && ver[2] == 0 && ver[3] < 11)
    ) 
  ) ||
  (ver[0] == 2 && ver[1] == 0 && ver[2] == 0 && ver[3] < 3)
) security_warning(get_kb_item("SMB/transport"));
