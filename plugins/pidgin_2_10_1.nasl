#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57318);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2011/12/19 00:43:48 $");

  script_cve_id(
    "CVE-2011-3594",
    "CVE-2011-4601",
    "CVE-2011-4602",
    "CVE-2011-4603"
  );
  script_bugtraq_id(49912, 51010, 51070, 51074);
  script_osvdb_id(75994, 77749, 77750, 77751);

  script_name(english:"Pidgin < 2.10.1 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An instant messaging client installed on the remote Windows host is
potentially affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Pidgin installed on the remote host is earlier than
2.10.1 and is potentially affected by the following issues :

  - A failure to validate input during the processing of 
    UTF-8 SILC protocol messages can cause the application
    to crash. (CVE-2011-3594, CVE-2011-4603)

  - A failure to validate input during the processing of 
    UTF-8 Oscar protocol buddy authorization request and 
    response messages can cause the application to crash.
    (CVE-2011-4601)

  - An error exists in the validation of voice and chat 
    messages in the XMPP protocol that can cause the 
    application to crash. (CVE-2011-4602)");
  script_set_attribute(attribute:"see_also",value:"http://developer.pidgin.im/wiki/ChangeLog");
  script_set_attribute(attribute:"see_also",value:"http://pidgin.im/news/security/?id=56");
  script_set_attribute(attribute:"see_also",value:"http://pidgin.im/news/security/?id=57");
  script_set_attribute(attribute:"see_also",value:"http://pidgin.im/news/security/?id=58");
  script_set_attribute(attribute:"see_also",value:"http://pidgin.im/news/security/?id=59");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Pidgin 2.10.1 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/15");

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
fixed_version = '2.10.1';

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
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "The Pidgin " + version + " install is not affected.");
