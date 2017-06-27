#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(56872);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/19 01:42:50 $");

  script_cve_id("CVE-2008-3434");
  script_bugtraq_id(50672);
  script_osvdb_id(48328);

  script_name(english:"Apple iTunes < 10.5.1 Update Authenticity Verification Weakness (credentialed check)");
  script_summary(english:"Checks version of iTunes on Windows");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains an application that is susceptible to a
man-in-the-middle attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Apple iTunes installed on the remote Mac OS X host is
earlier than 10.5.1. As such, it uses an unsecured HTTP connection
when checking for or retrieving software updates, which could allow a
man-in-the-middle attacker to provide a Trojan horse update that
appears to originate from Apple."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/bugtraq/2008/Jul/249"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"https://support.apple.com/kb/HT5030"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2011/Nov/msg00003.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Apple iTunes 10.5.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("itunes_detect.nasl");
  script_require_keys("SMB/iTunes/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("SMB/iTunes/Version");
fixed_version = "10.5.1.42";

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  if (report_verbosity > 0)
  {
    path = get_kb_item("SMB/iTunes/Path");
    if (isnull(path)) path = 'n/a';

    report =
      '\n  Path              : '+path+
      '\n  Installed version : '+version+
      '\n  Fixed version     : '+fixed_version+'\n';
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
}
else exit(0, "The iTunes " + version + " install on the host is not affected.");
