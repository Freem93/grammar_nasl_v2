#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(53844);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/17 16:53:09 $");

  script_cve_id("CVE-2011-2074");
  script_bugtraq_id(47747);
  script_osvdb_id(72232);

  script_name(english:"Skype for Mac 5.x < 5.1.0.922 Unspecified Remote Code Execution (credentialed check)");
  script_summary(english:"Checks version of Skype from Info.plist");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Mac OS X host has an application that allows arbitrary
code execution."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the instance of Skype installed on the
remote Mac OS X host reportedly allows an attacker to send a specially
crafted message to a user on the affected host and execute arbitrary
code. 

Note that by default, such a message would have to come from someone
in a user's Skype Contact List."
  );
  # http://www.purehacking.com/blogs/gordon-maddern/skype-0day-vulnerabilitiy-discovered-by-pure-hacking
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a8cef8d");
  # http://blogs.skype.com/security/2011/05/security_vulnerability_in_mac.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c36790c1");
  script_set_attribute(attribute:"solution", value:"Upgrade to Skype for Mac 5.1.0.922 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:skype:skype");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_skype_installed.nasl");
  script_require_keys("MacOSX/Skype/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("MacOSX/Skype/Version");
fixed_version = "5.1.0.922";

if (
  version =~ "^5\." && 
  ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : '+fixed_version+'\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else exit(0, "Skype for Mac "+version+" is installed and thus not affected.");
