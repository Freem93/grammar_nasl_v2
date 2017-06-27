#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(43862);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2010-0013");
  script_bugtraq_id(37524);
  script_osvdb_id(61420);
  script_xref(name:"Secunia", value:"37953");

  script_name(english:"Pidgin MSN Custom Smileys Feature Emoticon Request Traversal Arbitrary File Disclosure");
  script_summary(english:"Does a version check");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An instant messaging client installed on the remote Windows host is
affected by a directory traversal vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Pidgin installed on the remote host is earlier than
2.6.5.  Such versions have a directory traversal vulnerability when
processing an MSN emoticon request.  A remote attacker could exploit
this to read arbitrary files."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://events.ccc.de/congress/2009/Fahrplan/events/3596.en.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.pidgin.im/news/security/?id=42"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Pidgin 2.6.5 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22);
  script_set_attribute(attribute:"vuln_publication_date",value:"2009/12/27");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/01/08");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/01/12");
 script_cvs_date("$Date: 2016/05/16 14:22:06 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pidgin:pidgin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("pidgin_installed.nasl");
  script_require_keys("SMB/Pidgin/Version");

  exit(0);
}


include("global_settings.inc");


version = get_kb_item("SMB/Pidgin/Version");
if (isnull(version)) exit(1, "The 'SMB/Pidgin/Version' KB item is missing.");

ver_fields = split(version, sep:'.', keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);
rev = int(ver_fields[2]);

# Versions < 2.6.5 are affected
if (
  major < 2 ||
  (major == 2 && minor < 6) ||
  (major == 2 && minor == 6 && rev < 5)
)
{
  port = get_kb_item("SMB/transport");

  if(report_verbosity > 0)
  {
    report =
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 2.6.5\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "Version " + version + " is not affected.");

