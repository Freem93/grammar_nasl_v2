#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55928);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2011/10/24 19:37:28 $");

  script_cve_id("CVE-2011-2943", "CVE-2011-3184", "CVE-2011-3185");
  script_bugtraq_id(49268);
  script_osvdb_id(74825, 74826, 74827);

  script_name(english:"Pidgin < 2.10.0 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An instant messaging client installed on the remote Windows host
has multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Pidgin installed on the remote host is earlier than
2.10.0.  As such, it is potentially affected by the following issues :

  - A code execution vulnerability caused by clicking on a
    file:// URI received in an IM that Pidgin will attempt
    to execute.  This can result in the execution of 
    attacker-controlled code if the file is located on a 
    network share. (CVE-2011-3185)

  - A denial of service in the IRC protocol plugin caused
    by processing a specially crafted nickname when listing
    the set of users. (CVE-2011-2943)

  - A denial of service in the MSN protocol plugin caused
    by incorrect handling of HTTP 100 responses.  This only
    affects users who have enabled the HTTP connection 
    method, which is disabled by default. (CVE-2011-3184)"
  );
  script_set_attribute(attribute:"see_also",value:"http://www.insomniasec.com/advisories/ISVA-110822.1.htm");
  script_set_attribute(attribute:"see_also",value:"http://www.securityfocus.com/archive/1/519391/30/0/threaded");
  script_set_attribute(attribute:"see_also",value:"http://pidgin.im/news/security/?id=53");
  script_set_attribute(attribute:"see_also",value:"http://pidgin.im/news/security/?id=54");
  script_set_attribute(attribute:"see_also",value:"http://pidgin.im/news/security/?id=55");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Pidgin 2.10.0 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pidgin:pidgin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");

  script_dependencies("pidgin_installed.nasl");
  script_require_keys("SMB/Pidgin/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Pidgin/Version");
fixed_version = '2.10.0';

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  path = get_kb_item_or_exit("SMB/Pidgin/Path");
  port = get_kb_item("SMB/transport");

  if (report_verbosity > 0)
  {
    report =
      '\n  Path               : ' + path +
      '\n  Installed version  : ' + version +
      '\n  Fixed version      : ' + fixed_version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "Pidgin " + version + " is installed and hence not affected.");
